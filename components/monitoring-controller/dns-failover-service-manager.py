#!/usr/bin/env python3
"""
DNS-Failover daemon.

1. Читает YAML-конфигурацию из Consul KV.
2. Фильтрует endpoints, назначенные текущему SITE.
3. Выполняет проверки в Python и обновляет TTL checks локального Consul agent.

Переменные:
    SITE                    имя демона (обязательно)
    NODE_NAME               имя хоста. На случай нескольких демонов в HA
    SERVICE_NAME_PREFIX     префикс имени сервисов
    CONSUL_ADDR             URL локального агента (в Kubernetes: https://POD_IP:8501)
    CONSUL_HTTP_TOKEN       ACL-токен Consul (если ACL включены)
    CONSUL_CACERT           CA для проверки Consul servers
    CONSUL_AUTO_ENCRYPT_CA_ADDR  HTTPS URL server API, откуда получить Auto Encrypt CA
    CONSUL_KV_PATH          путь к yaml-файлу-конфигу в Consul хранилище
    BLOCKING_WAIT           время на блокировку очереди (по умолчанию 5м)
    HTTP_TIMEOUT_BLOCKING   HTTP-таймаут для blocking-query (по умолчанию: 330с)
    HEARTBEAT_INTERVAL      интервал INFO-сообщений о работающем KV watch (по умолчанию: 3600с)
    ALLOW_EMPTY_BOOTSTRAP   можно ли сносить managed-сервисы при пустом конфиге на холодном старте (по умолчанию: false)
    LOG_LEVEL               уровень логирования (по умолчанию INFO)
    MANAGED_TAG             тег для регистрируемых сервисов

Script checks в Consul agent не используются и должны оставаться выключенными.
"""
from __future__ import annotations

import base64
import logging
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import requests
import yaml
import hashlib
import json
import re

from dataclasses import dataclass, field, replace
from enum import Enum
from requests.adapters import HTTPAdapter
from types import FrameType
from typing import Any, Dict, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# Конфигурация                                                                #
# --------------------------------------------------------------------------- #
# SlugHelper для zone_name
_SLUG_RE = re.compile(r"[^a-zA-Z0-9_-]+")


class CheckResult(Enum):
    """Результат active check до преобразования в Consul TTL status."""

    PASS = "PASS"      # Цель подтвердила доступность.
    FAIL = "FAIL"      # Проверка выполнена, цель недоступна.
    ERROR = "ERROR"    # Саму проверку выполнить корректно не удалось.


def _envbool(name: str, default: bool) -> bool:
    """Безопасный парсинг bool из переменных окружения."""
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


@dataclass(frozen=True)
class Config:
    site: str
    node_name: Optional[str]
    scope_tag: str
    service_name_prefix: str
    consul_addr: str
    consul_http_token: Optional[str]
    consul_cacert: Optional[str]
    consul_auto_encrypt_ca_addr: Optional[str]
    consul_ca_bundle_pem: Optional[str]
    consul_kv_path: str
    blocking_wait: str
    managed_tag: str
    http_timeout_blocking: int
    heartbeat_interval: int
    http_timeout_short: int = 10
    allow_empty_bootstrap: bool = False
    backoff_base: float = 1.0
    backoff_cap: float = 60.0


    @staticmethod
    def from_env() -> Config:
        if "SITE" not in os.environ:
            raise KeyError("Определите переменную окружения 'SITE'.")
        site = os.environ["SITE"]
        node_name = os.environ.get("NODE_NAME")
        if not node_name:
            raise KeyError("Определите уникальную переменную окружения 'NODE_NAME'.")

        scope_tag = f"daemon-site-{site}-node-{node_name}"
        consul_kv_path = os.environ.get("CONSUL_KV_PATH")
        if not consul_kv_path:
            raise KeyError("Определите переменную окружения 'CONSUL_KV_PATH'.")

        return Config(
            site=site,
            node_name=node_name,
            scope_tag=scope_tag,
            service_name_prefix=os.environ.get("SERVICE_NAME_PREFIX", "dns-failover"),
            consul_addr=os.environ.get("CONSUL_ADDR", "http://127.0.0.1:8500").rstrip("/"),
            consul_http_token=os.environ.get("CONSUL_HTTP_TOKEN") or None,
            consul_cacert=os.environ.get("CONSUL_CACERT") or None,
            consul_auto_encrypt_ca_addr=(
                os.environ.get("CONSUL_AUTO_ENCRYPT_CA_ADDR", "").rstrip("/") or None
            ),
            consul_ca_bundle_pem=None,
            consul_kv_path=consul_kv_path,
            blocking_wait=os.environ.get("BLOCKING_WAIT", "5m"),
            managed_tag=os.environ.get("MANAGED_TAG", "dns-failover-managed"),
            http_timeout_blocking=int(os.environ.get("HTTP_TIMEOUT_BLOCKING", "330")),
            heartbeat_interval=int(os.environ.get("HEARTBEAT_INTERVAL", "3600")),
            http_timeout_short=10,
            allow_empty_bootstrap=_envbool("ALLOW_EMPTY_BOOTSTRAP", False)
        )

# --------------------------------------------------------------------------- #
# Логирование                                                                 #
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("consul-service-manager")

# --------------------------------------------------------------------------- #
# Управление завершением работы                                               #
# --------------------------------------------------------------------------- #
class Shutdown:
    """Флаг корректного завершения работы, не прерывая транзакции"""


    def __init__(self) -> None:
        self.stop: bool = False
        # Перехватываем сигналы
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)


    def _handle(self, signum: int, frame: Optional[FrameType]) -> None:
        log.info("Получил сигнал %d, завершаю работу", signum)
        self.stop = True
        raise SystemExit(0)


    def sleep(self, seconds: float) -> None:
        # Режим ожидания. Выходим из него, если было запрошено завершение работы
        deadline = time.monotonic() + seconds
        while not self.stop:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.5, remaining))

# --------------------------------------------------------------------------- #
# Читаем yaml-файл, формируем объект и правила проверки                       #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DesiredService:
    """
    Чертёж сервиса. Преобразует YAML в формат Consul и генерирует уникальный ID
    """
    service_id: str
    name: str
    address: str
    tags: Tuple[str, ...]
    check: Dict[str, Any]
    check_proto: str
    interval_seconds: float
    timeout_seconds: float
    success_before_passing: int
    failures_before_warning: int
    failures_before_critical: int
    meta: Dict[str, str] = field(default_factory=dict)


    def config_hash(self) -> str:
        """SHA256 от всех полей, влияющих на поведение сервиса/чека."""
        material = {
            "name":    self.name,
            "address": self.address,
            "tags":    sorted(self.tags),
            "check":   self.check,
            "interval_seconds": self.interval_seconds,
            "timeout_seconds": self.timeout_seconds,
            "success_before_passing": self.success_before_passing,
            "failures_before_warning": self.failures_before_warning,
            "failures_before_critical": self.failures_before_critical,
            "meta":    {k: v for k, v in self.meta.items() if k != "config_hash"},
        }
        # sort_keys=True гарантирует детерминированность
        blob = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


    @staticmethod
    def build(
        cfg: Config,
        zone_name: str,
        dns_provider: str,
        provider_meta: Dict[str, str],
        record_dict: Dict[str, Any],
        ep: Dict[str, Any],
        defaults: Optional[Dict[str, Any]] = None) -> DesiredService:
        """
        Трансформирует секцию из YAML в объект DesiredService.
        Приоритет: endpoints > records > defaults.
        """
        defaults = defaults or {}
        def_check = (defaults.get("check") or {})
        record   = record_dict["name"]
        ttl      = int(record_dict.get("ttl", defaults.get("ttl", 60)))
        on_fail  = record_dict.get("on_all_fail", "keep")
        fallback = record_dict.get("fallback_ip", "")

        if on_fail not in ("keep", "remove", "fallback"):
            raise ValueError(f"on_all_fail={on_fail!r} некорректно")
        if on_fail == "fallback" and not fallback:
            raise ValueError(f"on_all_fail=fallback требует fallback_ip")

        ip        = ep["ip"]
        uplink_provider = ep["uplink_provider"]
        chk       = ep["check"]
        target    = chk.get("target", ip)
        sites     = ep.get("sites") or []
        num_sites = len(sites)
        owner_site = ep.get("owner_site") or record_dict.get("owner_site")
        if not owner_site:
            raise ValueError(f"owner_site не задан для endpoint={ip}, record={record}")

        # Приоритет: endpoints (ep) > records (record_dict) > defaults
        raw_quorum = ep.get("quorum")
        if raw_quorum is None:
            raw_quorum = defaults.get("quorum")
        if raw_quorum is None:
            raise ValueError(f"Значение для кворума не задано ни на одном уровне для endpoint={ip}, record={record}")
        try:
            quorum = int(raw_quorum)
        except (ValueError, TypeError) as err:
            raise ValueError(f"Некорректный формат значения quorum: {raw_quorum!r}. Нужен int.") from err
        if quorum < 1:
            raise ValueError(f"Значение quorum должно быть >= 1, а передано {quorum}")
        if quorum > num_sites:
            raise ValueError(f"quorum={quorum} не может быть больше кол-ва sites {num_sites} для эндпоинта {record} {ip}")

        raw_minimum_observers = ep.get("minimum_observers")
        if raw_minimum_observers is None:
            raw_minimum_observers = record_dict.get("minimum_observers", defaults.get("minimum_observers", quorum))
        minimum_observers = int(raw_minimum_observers)
        if minimum_observers < 1 or minimum_observers > num_sites:
            raise ValueError(
                f"minimum_observers={minimum_observers} должен быть от 1 до числа sites={num_sites} "
                f"для endpoint={ip}, record={record}"
            )

        interval = chk.get("interval", def_check.get("interval"))
        timeout  = chk.get("timeout", def_check.get("timeout"))
        if not interval or not timeout:
            raise ValueError(f"check.interval/timeout не заданы для endpoint={ep!r}")
        kind     = chk["kind"].lower()

        sbp  = chk.get("success_before_passing", def_check.get("success_before_passing"))
        fbw  = chk.get("failures_before_warning", def_check.get("failures_before_warning"))
        fbc  = chk.get("failures_before_critical", def_check.get("failures_before_critical"))
        sbp_val = max(1, int(sbp or 1))
        fbw_val = max(1, int(fbw or 1))
        fbc_val = max(1, int(fbc or 1))
        interval_seconds = _parse_duration(interval)
        timeout_seconds = _parse_duration(timeout)

        # --------------------------------------------------------------------------- #
        # Проверки                                                                    #
        # --------------------------------------------------------------------------- #
        if kind == "tcp":
            port = chk.get("port")
            if not port:
                raise ValueError(f"check.port обязателен для TCP endpoint={ip}")

        elif kind == "icmp":
            pass

        elif kind == "smtp":
            port = chk.get("port", 25)

        elif kind == "http":
            if "url" in chk:
                url = chk["url"]
            else:
                scheme = chk.get("scheme", "http")
                port   = chk.get("port")
                if not port:
                    raise ValueError(f"check.port обязателен для HTTP endpoint={ip}, если check.url не задан")
                path   = chk.get("path") or "/"
                if not path.startswith("/"):
                    path = "/" + path
                url = f"{scheme}://{target}:{port}{path}"
            chk = {**chk, "url": url}
        else:
            raise ValueError(f"Неизвестное значение check.kind={kind!r}")

        # точки ломают dns-имена в Consul
        zone_slug = _slug(zone_name)
        record_slug = _slug(record)
        dns_prov_slug = _slug(dns_provider)

        sid  = f"failover-{cfg.site}-{dns_prov_slug}-{record_slug}-{zone_slug}-{uplink_provider}-{ip}"
        name = f"{cfg.service_name_prefix}-{dns_prov_slug}-{record_slug}-{zone_slug}"
        tags = [
            cfg.site,
            cfg.managed_tag,
            cfg.scope_tag,
            f"record-{record_slug}",
            f"zone-{zone_slug}",
            f"dns-provider-{dns_prov_slug}",
            f"uplink_provider-{uplink_provider}",
        ]
        meta = {
            "ttl": str(ttl),
            "site": cfg.site,
            "uplink_provider": uplink_provider,
            "zone": zone_name,
            "dns_provider": dns_provider,
            "record": record,
            "check_target": target,
            "owner_site": str(owner_site),
            "on_all_fail": on_fail,
            "fallback_ip": fallback,
            "quorum": str(quorum),
            "minimum_observers": str(minimum_observers),
            **provider_meta  # Динамические поля провайдеров == новые поля попадают сюда
        }
        return DesiredService(
            sid, name, ip, tuple(tags), dict(chk), kind,
            interval_seconds, timeout_seconds, sbp_val, fbw_val, fbc_val, meta,
        )


    def to_payload(self) -> Dict[str, Any]:
        meta_with_hash = {**self.meta, "config_hash": self.config_hash()}
        return {
            "ID":      self.service_id,
            "Name":    self.name,
            "Address": self.address,
            "Tags":    list(self.tags),
            "Meta":    meta_with_hash,
            "Check": {
                "CheckID": self.check_id,
                "Name": f"{self.check_proto} check from {self.meta['site']}",
                "TTL": f"{max(30, int(self.interval_seconds * 3 + self.timeout_seconds))}s",
                # До первой выполненной проверки состояние неизвестно.
                "Status": "warning",
                "DeregisterCriticalServiceAfter": "0s",
            },
        }

    @property
    def check_id(self) -> str:
        return f"dns-failover:{self.service_id}"


def _has_drift(current: Dict[str, Any], desired: DesiredService) -> bool:
    """
    True -> перегистрируем.

    Сравниваем config_hash из Meta. Если хэша нет (старый сервис, до апгрейда
    демона), то считаем drift и регистрируем заново, чтобы записать хэш.
    """
    current_hash = (current.get("Meta") or {}).get("config_hash")
    if not current_hash:
        log.info("У сервиса id=%s нет config_hash -- миграция, регистрируем заново",
                 current.get("ID"))
        return True
    return current_hash != desired.config_hash()


def _slug(value: str) -> str:
    """
    Приводит строку к виду, безопасному для Consul: оставляем [A-Za-z0-9_-],
    всё остальное изменяем на '-'.
    Пример: 'app.example.com' -> 'app-example-com'.
    """
    return _SLUG_RE.sub("-", value).strip("-")


def _parse_duration(value: Any) -> float:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)\s*", str(value))
    if not match:
        raise ValueError(f"Некорректная длительность {value!r}; ожидается, например, 500ms, 15s, 2m")
    number = float(match.group(1))
    return number * {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}[match.group(2)]

# --------------------------------------------------------------------------- #
# Consul HTTP-клиент                                                          #
# --------------------------------------------------------------------------- #
class KVUnavailable(Exception):
    """Consul KV временно недоступен (сеть/5xx). Reconcile не выполнять."""


class InvalidDesiredState(Exception):
    """Конфигурация некорректна. Текущее состояние нельзя частично удалять."""


def _raise_with_body(r: requests.Response, what: str) -> None:
    if r.status_code >= 400:
        body = (r.text or "").strip().replace("\n", " ")[:500]
        raise requests.HTTPError(
            f"{what}: HTTP {r.status_code} {r.reason} -- {body}",
            response=r,
        )


def with_auto_encrypt_ca_bundle(cfg: Config) -> Config:
    """Получить service-mesh CA через server API и вернуть config с CA bundle.

    Server API проверяется статическим Consul Agent CA. Полученные roots нужны
    для проверки HTTPS-сертификата локального client agent, выданного через
    Auto Encrypt. Bundle хранится в памяти процесса.
    """
    if not cfg.consul_auto_encrypt_ca_addr:
        return cfg
    if not cfg.consul_cacert:
        raise ValueError(
            "CONSUL_CACERT обязателен при использовании CONSUL_AUTO_ENCRYPT_CA_ADDR"
        )

    headers = {}
    if cfg.consul_http_token:
        headers["X-Consul-Token"] = cfg.consul_http_token
    url = f"{cfg.consul_auto_encrypt_ca_addr}/v1/connect/ca/roots"
    response = requests.get(
        url,
        headers=headers,
        timeout=cfg.http_timeout_short,
        verify=cfg.consul_cacert,
    )
    _raise_with_body(response, "Получаем Consul Auto Encrypt CA")
    payload = response.json()

    certificates = []
    for root in payload.get("Roots") or []:
        root_cert = root.get("RootCert")
        if root_cert:
            certificates.append(root_cert.strip())
        certificates.extend(
            cert.strip()
            for cert in (root.get("IntermediateCerts") or [])
            if cert and cert.strip()
        )
    if not certificates:
        raise ValueError(f"Consul не вернул CA certificates через {url}")

    # Включаем оба trust anchors: Agent CA и Auto Encrypt/service-mesh CA.
    with open(cfg.consul_cacert, "r", encoding="utf-8") as source:
        certificates.insert(0, source.read().strip())
    unique_certificates = list(dict.fromkeys(certificates))

    bundle_pem = "\n".join(unique_certificates) + "\n"
    log.info("Получен Auto Encrypt CA; TLS bundle подготовлен в памяти")
    return replace(cfg, consul_ca_bundle_pem=bundle_pem)


class SSLContextAdapter(HTTPAdapter):
    """
    Requests adapter с CA certificates из памяти, без временного файла.
    POD запускается с readOnlyRootFilesystem: true, поэтому /tmp не создаётся.
    """

    def __init__(self, context: ssl.SSLContext) -> None:
        self.context = context
        super().__init__()

    def init_poolmanager(self, connections: int, maxsize: int,
                         block: bool = False, **pool_kwargs: Any) -> None:
        pool_kwargs["ssl_context"] = self.context
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        proxy_kwargs["ssl_context"] = self.context
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class ConsulClient:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.base_url = cfg.consul_addr.rstrip("/")
        # Sessions повторно использует tcp-соединения
        self.session = requests.Session()
        if cfg.consul_ca_bundle_pem:
            context = ssl.create_default_context()
            context.load_verify_locations(cadata=cfg.consul_ca_bundle_pem)
            self.session.mount("https://", SSLContextAdapter(context))
        elif cfg.consul_cacert:
            self.session.verify = cfg.consul_cacert
        # Заголовок ACL-токена Consul, если ACL не включены агент игнорирует заголовок
        if cfg.consul_http_token:
            self.session.headers["X-Consul-Token"] = cfg.consul_http_token
            log.debug("Используем ACL-токен из CONSUL_HTTP_TOKEN")
        else:
            log.debug("CONSUL_HTTP_TOKEN не задан -- работаем без ACL-токена")


    def deregister(self, service_id: str) -> None:
        r = self.session.put(f"{self.base_url}/v1/agent/service/deregister/{service_id}",
                             timeout=self.cfg.http_timeout_short)
        _raise_with_body(r, f"Дерегистрируем id={service_id}")


    def agent_self(self) -> Dict[str, Any]:
        r = self.session.get(f"{self.base_url}/v1/agent/self", timeout=self.cfg.http_timeout_short)
        r.raise_for_status()
        return r.json()


    # Читаем KV
    def kv_read(self, key: str, index: Optional[int], wait: Optional[str]) -> Tuple[Optional[str], int]:
        """
        Возвращает (value, new_index)
        value = None -- http 404 (файла на пути нет), состояние "конфиг удалён"
        value = "" -- файл пуст
        value = "..." -- ок

        Поднимает
        requests.exceptions.ReadTimeout -- blocking-query истёк -- ок
        KVUnvailable -- при любой другой ошибке
        """
        params: Dict[str, str] = {}
        if wait:
            params["wait"] = wait
        if index is not None and index > 0:
            params["index"] = str(index)

        timeout = self.cfg.http_timeout_blocking if wait and index else self.cfg.http_timeout_short
        url = f"{self.base_url}/v1/kv/{key}"

        try:
            r = self.session.get(url, params=params, timeout=timeout)
        except requests.exceptions.ReadTimeout:
            raise
        except requests.exceptions.RequestException as e:
            # ConnectionError, DNS, прочее
            raise KVUnavailable(f"Сетевая ошибка до Consul KV: {e}") from e

        new_index = int(r.headers.get("X-Consul-Index", "0"))

        if r.status_code == 404:
            return None, new_index

        if r.status_code >= 500:
            raise KVUnavailable(f"Consul вернул {r.status_code}: {r.text[:200]}")

        try:
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise KVUnavailable(f"HTTP-ошибка: {e}") from e

        body = r.json()
        if not body:
            return None, new_index
        raw = body[0].get("Value")
        if raw is None:
            return "", new_index
        return base64.b64decode(raw).decode("utf-8"), new_index


    # Список сервисов
    def list_managed_services(self) -> Dict[str, Dict[str, Any]]:
        # Список сервисов через агента. API отличается от обращения к серверу
        url = f"{self.base_url}/v1/agent/services"
        # Консул фильтрует на стороне сервера
        params = {"filter": f'"{self.cfg.managed_tag}" in Tags and "{self.cfg.scope_tag}" in Tags'}
        r = self.session.get(url, params=params, timeout=self.cfg.http_timeout_short)
        r.raise_for_status()
        services: Dict[str, Dict[str, Any]] = r.json() or {}

        # Проверка тега, если фильтр на стороне сервера не отработал
        return {
            sid: svc
            for sid, svc in services.items()
            if self.cfg.managed_tag in (svc.get("Tags") or [])
            and self.cfg.scope_tag in (svc.get("Tags") or [])
        }


    def register(self, payload: Dict[str, Any]) -> None:
        """Регистрация сервиса через агента"""
        # Регистрация через агента отличается от регистрации напрямую на сервере
        url = f"{self.base_url}/v1/agent/service/register"
        r = self.session.put(url, json=payload, params={"replace-existing-checks": "true"},
                             timeout=self.cfg.http_timeout_short)
        _raise_with_body(r, f"register id={payload.get('ID')}")

    def update_ttl(self, check_id: str, status: str, output: str) -> None:
        endpoint = {"passing": "pass", "warning": "warn", "critical": "fail"}[status]
        r = self.session.put(
            f"{self.base_url}/v1/agent/check/{endpoint}/{check_id}",
            params={"note": output[:512]},
            timeout=self.cfg.http_timeout_short,
        )
        _raise_with_body(r, f"TTL проверка {check_id} -> {status}")


def _execute_check(desired: DesiredService) -> Tuple[CheckResult, str]:
    check = desired.check
    target = str(check.get("target", desired.address))
    timeout = desired.timeout_seconds

    try:
        if desired.check_proto == "icmp":
            timeout_arg = max(1, int(timeout))
            completed = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout_arg), target],
                capture_output=True,
                text=True,
                timeout=timeout + 1,
                check=False,
            )
            output = (completed.stdout or completed.stderr or "ping failed").strip().splitlines()[-1]
            if completed.returncode == 0:
                return CheckResult.PASS, output
            if completed.returncode == 1:
                return CheckResult.FAIL, output
            return CheckResult.ERROR, (
                f"ICMP check execution error (ping rc={completed.returncode}): {output}"
            )

        if desired.check_proto == "tcp":
            port = int(check["port"])
            with socket.create_connection((target, port), timeout=timeout):
                return CheckResult.PASS, f"TCP {target}:{port} connected"

        if desired.check_proto == "smtp":
            port = int(check.get("port", 25))
            with socket.create_connection((target, port), timeout=timeout) as connection:
                connection.settimeout(timeout)
                banner = connection.recv(1024).decode("utf-8", errors="replace").strip()
                if banner.startswith("220"):
                    connection.sendall(b"QUIT\r\n")
                    return CheckResult.PASS, banner
                return CheckResult.FAIL, banner or "SMTP сервер отдал пустой ответ"

        if desired.check_proto == "http":
            verify: Any = not bool(check.get("tls_skip_verify"))
            response = requests.request(
                str(check.get("method", "GET")),
                str(check["url"]),
                headers=check.get("header"),
                timeout=timeout,
                verify=verify,
                allow_redirects=bool(check.get("follow_redirects", True)),
            )
            result = CheckResult.PASS if response.status_code < 400 else CheckResult.FAIL
            return result, f"HTTP {response.status_code}"
    except (OSError, subprocess.SubprocessError, requests.RequestException) as error:
        result = CheckResult.ERROR if desired.check_proto == "icmp" else CheckResult.FAIL
        return result, f"{type(error).__name__}: {error}"

    return CheckResult.ERROR, f"неподдерживаемый тип проверки: {desired.check_proto}"


class ActiveCheckWorker:
    def __init__(self, consul: ConsulClient, desired: DesiredService) -> None:
        # requests.Session не разделяем между blocking KV watch и worker threads.
        self.consul = ConsulClient(consul.cfg)
        self.desired = desired
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name=f"check-{desired.service_id}",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def join(self) -> None:
        self.thread.join(timeout=self.desired.timeout_seconds + 2)

    def _run(self) -> None:
        successes = 0
        failures = 0
        last_status: Optional[str] = None

        while not self.stop_event.is_set():
            started = time.monotonic()
            result, output = _execute_check(self.desired)
            if result is CheckResult.PASS:
                successes += 1
                failures = 0
                status = "passing" if successes >= self.desired.success_before_passing else (last_status or "warning")
            elif result is CheckResult.FAIL:
                failures += 1
                successes = 0
                if failures >= self.desired.failures_before_warning + self.desired.failures_before_critical:
                    status = "critical"
                elif failures >= self.desired.failures_before_warning:
                    status = "warning"
                else:
                    status = last_status or "warning"
            else:
                # Локальная ошибка проверки не доказывает недоступность цели.
                # Сбрасываем серии и публикуем unknown как TTL warning.
                successes = 0
                failures = 0
                status = "warning"
                output = f"ERROR: {output}"
                log.error(
                    "check=%s result=ERROR target=%s output=%s",
                    self.desired.check_id,
                    self.desired.check.get("target", self.desired.address),
                    output,
                )

            try:
                self.consul.update_ttl(self.desired.check_id, status, output)
                if status != last_status:
                    if last_status is None:
                    # Первая публикация после запуска -- начальное наблюдение,
                    # а не изменение состояния сервиса.
                        log.info(
                            "check=%s initial_status=%s output=%s",
                            self.desired.check_id,
                            status,
                            output,
                        )
                    elif status == "passing":
                        log.info(
                            "check=%s status=%s->%s output=%s",
                            self.desired.check_id,
                            last_status,
                            status,
                            output,
                        )
                    else:
                        log.warning(
                            "check=%s status=%s->%s output=%s",
                            self.desired.check_id,
                            last_status,
                            status,
                            output,
                        )
                last_status = status
            except requests.RequestException as error:
                log.error("Не удалось обновить TTL check=%s: %s", self.desired.check_id, error)

            elapsed = time.monotonic() - started
            self.stop_event.wait(max(0.1, self.desired.interval_seconds - elapsed))


class ActiveCheckSet:
    def __init__(self, consul: ConsulClient) -> None:
        self.consul = consul
        self.workers: Dict[str, ActiveCheckWorker] = {}

    def replace(self, desired: Dict[str, DesiredService]) -> None:
        for worker in self.workers.values():
            worker.stop()
        for worker in self.workers.values():
            worker.join()
        self.workers = {sid: ActiveCheckWorker(self.consul, item) for sid, item in desired.items()}
        for worker in self.workers.values():
            worker.start()
        log.info("Запущено active checks: %d", len(self.workers))

    def stop(self) -> None:
        self.replace({})

# --------------------------------------------------------------------------- #
# Парсим конфиг. Проверяем, что он корректный                                 #
# --------------------------------------------------------------------------- #
def parse_desired_state(yaml_text: str, cfg: Config) -> Dict[str, DesiredService]:
    """Парсим yaml-строку в {service_id: DesiredService}. С проверкой на ошибки."""
    if not yaml_text or not yaml_text.strip():
        return {}
    try:
        doc = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as e:
        raise InvalidDesiredState(f"Ошибка YAML: {e}") from e

    defaults = doc.get("defaults") or {}
    # Задаем ключевые константные поля схемы, чтобы отсечь их от метаданных провайдеров
    KNOWN_ZONE_KEYS = {"zone_name", "dns_provider", "records"}

    desired: Dict[str, DesiredService] = {}
    # Проходим по всем зонам в конифге
    for i, zone in enumerate(doc.get("zones", []) or []):
        zone_name = zone.get("zone_name")
        dns_provider = zone.get("dns_provider")

        if not zone_name or not dns_provider:
            raise InvalidDesiredState(
                f"В блоке zones[{i}] не указан zone_name или dns_provider"
            )

        # Всё, что не входит в KNOWN_ZONE_KEYS, объявляется параметром провайдера -- заносится в meta
        provider_meta: Dict[str, str] = {
            k: str(v)
            for k, v in zone.items()
            if k not in KNOWN_ZONE_KEYS and v is not None
        }

        for record in zone.get("records", []) or []:
            rec_name = record.get("name")
            if not rec_name:
                raise InvalidDesiredState(f"zone={zone_name}: запись без name")
            for ep in record.get("endpoints", []) or []:
                sites = ep.get("sites")
                # Если site в yaml-конфиге указан не этого демона, то пропускаем
                if not sites or cfg.site not in sites:
                    continue
                ip = ep.get("ip")
                check_proto = ep.get("check")
                if not ip or not check_proto:
                    raise InvalidDesiredState(
                        f"zone={zone_name} record={rec_name}: endpoint без ip/check: {ep!r}"
                    )
                try:
                    ds = DesiredService.build(
                        cfg,
                        zone_name=zone_name,
                        dns_provider=dns_provider,
                        provider_meta=provider_meta,
                        record_dict=record,
                        ep=ep,
                        defaults=defaults
                    )
                except (ValueError, KeyError, TypeError) as e:
                    raise InvalidDesiredState(
                        f"zone={zone_name} record={rec_name} endpoint={ep!r}: "
                        f"{type(e).__name__}: {e}"
                    ) from e
                if ds.service_id in desired:
                    raise InvalidDesiredState(f"Дубликат service_id={ds.service_id}")
                desired[ds.service_id] = ds
    return desired

# --------------------------------------------------------------------------- #
# Согласование сервисов                                                       #
# --------------------------------------------------------------------------- #
def reconcile(consul: ConsulClient, desired: Dict[str, DesiredService]) -> bool:
    """
    Согласуем разницу. Не вызывает исключение -- логируем и продолжаем
    Возвращает:
    - True, если все операции прошли успешно
    - False, если хотя бы одна [de]register прошла не успешно
    Главный цикл по этому флагу решает, двигать ли last_index
    """
    try:
        current = consul.list_managed_services()
    except requests.RequestException as e:
        log.error("Ошибка вывода текущих сервисов у агента: %s", e)
        return False

    current_ids: Set[str] = set(current.keys())
    desired_ids: Set[str] = set(desired.keys())

    to_add      = desired_ids - current_ids
    to_remove   = current_ids - desired_ids
    to_keep     = desired_ids & current_ids

    log.info("Согласование. Желаемое=%d, текущее у Агента=%d, добавляем=%d, удаляем=%d, сохраняем=%d",
             len(desired_ids), len(current_ids), len(to_add), len(to_remove), len(to_keep))

    all_ok = True

    # Регистрируем новый
    for sid in sorted(to_add):
        ds = desired[sid]
        try:
            consul.register(ds.to_payload())
            log.warning("Зарегистрированный сервис id=%s name=%s address=%s check=%s",
                     ds.service_id, ds.name, ds.address, ds.check_proto)
        except requests.RequestException as e:
            log.error("Регистрация id=%s провалилась: %s", sid, e)
            all_ok = False

    # Дрифт
    # Перегистрируем текущие сервисы, ели изменился config_hash.
    # ID сервиса не меняется
    for sid in sorted(to_keep):
        ds = desired[sid]
        if _has_drift(current[sid], ds):
            try:
                consul.register(ds.to_payload())
                log.info("Перерегистрирован сервис в дрифте id=%s", sid)
            except requests.RequestException as e:
                log.error("Перерегистрация id=%s провалилась: %s", sid, e)
                all_ok = False

    # Удаляем устаревшие ID
    for sid in sorted(to_remove):
        try:
            consul.deregister(sid)
            log.warning("Дерегистрация устаревшего сервиса id=%s", sid)
        except requests.RequestException as e:
            log.error("Дерегистрация id=%s провалилась: %s", sid, e)
            all_ok = False

    return all_ok

# --------------------------------------------------------------------------- #
# Проверка подключения к Consul                                               #
# Docker compose может запустить демон быстрее чем агент откроет 8500         #
# --------------------------------------------------------------------------- #
def wait_for_consul(consul: ConsulClient, shutdown: Shutdown) -> None:
    backoff = consul.cfg.backoff_base
    while not shutdown.stop:
        try:
            info = consul.agent_self()
            agent_cfg = info.get("Config", {})
            log.info("Локальный Consul-агент доступен (node=%s dc=%s version=%s)",
                     agent_cfg.get("NodeName", "?"), agent_cfg.get("Datacenter", "?"), agent_cfg.get("Version", "?"),)
            return
        except requests.RequestException as e:
            log.warning("Consul-агент пока не доступен: %s (повтор через %.1fс)",
                        e, backoff)
        shutdown.sleep(backoff)
        backoff = min(backoff * 2, consul.cfg.backoff_cap)

# --------------------------------------------------------------------------- #
# Главный цикл                                                                #
# --------------------------------------------------------------------------- #
def main() -> int:
    try:
        cfg = Config.from_env()
        cfg = with_auto_encrypt_ca_bundle(cfg)
    except Exception as e:
        log.error("Ошибка инициализации конфигурации окружения: %s", e)
        return 1

    log.info("Стартуем DNS-Failover Control Plane (consul=%s, kv=%s, wait=%s, allow_empty_bootstrap=%s)",
             cfg.consul_addr, cfg.consul_kv_path, cfg.blocking_wait, cfg.allow_empty_bootstrap)
    shutdown = Shutdown()
    consul = ConsulClient(cfg)
    active_checks = ActiveCheckSet(consul)

    wait_for_consul(consul, shutdown)
    if shutdown.stop:
        return 0

    # 1. Синкаем стейт. Чтение без блокировки
    log.info("Шаг 1. Первичная синхронизация состояния")
    last_index: int = 0
    backoff = cfg.backoff_base

    while not shutdown.stop:
        try:
            value, new_index = consul.kv_read(cfg.consul_kv_path, index=last_index, wait=cfg.blocking_wait)

        # порядок Exception важен!
        # ReadTimeout -- подкласс RequestException, который подкласс ConnectionError'а.
        # Если поменять местами blocking-query таймаут будет ошибочно приниматься за сбой и запускать backoff.
        # Consul держит blocking-query на (wait + wait/16)сек = 5мин + 18.75сек
        # HTTP_TIMEOUT_BLOCKING=330s должен быть обязательно больше!
        # https://developer.hashicorp.com/consul/api-docs/features/blocking

        except requests.exceptions.ReadTimeout:
            log.debug("Blocking query истёк по таймауту (норма), переподключаемся")
            continue

        except KVUnavailable as e:
            # Consul KV недоступен -> ничего не дерегистрируем, last_index сохраняем
            log.error("KV недоступен: %s (повтор через %.1fс)", e, backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
            continue

        except Exception as e:
            log.exception("Неожиданная ошибка: %s", e)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
            continue

        # Чтение успешно -- решаем, что делать с результатом
        config_missing = value is None
        try:
            desired = ({} if config_missing else parse_desired_state(value, cfg))
        except InvalidDesiredState as error:
            log.error("Некорректный desired config: %s. Существующие сервисы не изменяются.", error)
            last_index = new_index
            backoff = cfg.backoff_base
            shutdown.sleep(2.0)
            continue

        if config_missing:
            log.warning("KV-файл %s отсутствует (HTTP 404).", cfg.consul_kv_path)
        elif not desired:
            log.warning("KV-файл %s прочитан, но желаемых сервисов для site=%s = 0.",
                        cfg.consul_kv_path, cfg.site)
        else:
            log.info("Конфиг прочитан (index=%d), желаемых сервисов для site=%s: %d",
                     new_index, cfg.site, len(desired))

        # Защита на холодном старте:
        # при пустом/удалённом конфиге не дерегистрируем существующие managed-сервисы,а ждём появления валидного конфига.
        # Снимается флагом ALLOW_EMPTY_BOOTSTRAP=true.
        if not desired and not cfg.allow_empty_bootstrap:
            log.warning(
                "Bootstrap: желаемое состояние пусто, ALLOW_EMPTY_BOOTSTRAP=false -- "
                "пропускаем reconcile, чтобы не снести managed-сервисы. "
                "Жду валидный конфиг в KV (index=%d) ...",
                new_index,
            )
            # Двигаем индекс, иначе следующая итерация снова вернётся мгновенно
            last_index = new_index
            backoff = cfg.backoff_base
            shutdown.sleep(2.0)
            continue

        if reconcile(consul, desired):
            active_checks.replace(desired)
            last_index = new_index
            backoff = cfg.backoff_base
            break
        else:
            # Часть операций провалилась -- индекс не двигаем, повторим bootstrap после backoff.
            log.warning("Первичная синхронизация выполнена с ошибками, повторяем через %.1fс",
                        backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
            continue

    if shutdown.stop:
        log.info("Shutdown во время bootstrap")
        return 0

    # last_index здесь = X-Consul-Index ключа на момент bootstrap.
    # Шаг 2 использует его как стартовую точку blocking-query.
    log.info("Шаг 2. Выставляем дозор за KV (стартовый index=%d)", last_index)
    backoff = cfg.backoff_base
    outage_started: Optional[float] = None
    consecutive_failures = 0
    last_heartbeat = time.monotonic()

    while not shutdown.stop:
        query_started = time.monotonic()
        try:
            value, new_index = consul.kv_read(cfg.consul_kv_path, index=last_index, wait=cfg.blocking_wait)
            if shutdown.stop:
                break
            query_finished = time.monotonic()

            if outage_started is not None:
                log.info(
                    "Связь с Consul KV восстановлена: outage=%.1fс, попыток=%d, index=%d",
                    query_finished - outage_started,
                    consecutive_failures,
                    new_index,
                )
                outage_started = None
                consecutive_failures = 0

            if query_finished - last_heartbeat >= cfg.heartbeat_interval:
                log.info(
                    "KV watch работает: index=%d, последний запрос=%.1fс, ошибок подряд=%d",
                    new_index,
                    query_finished - query_started,
                    consecutive_failures,
                )
                last_heartbeat = query_finished

            if new_index < 1:
                new_index = 1
            if new_index < last_index:
                log.warning("X-Consul-Index откатился (%d -> %d), сброс таймера",
                            last_index, new_index)
                last_index = 0
                continue
            if new_index == last_index:
                # Заблокированный запрос вернулся без изменений по таймауту
                log.debug("У index=%d в KV нет изменений", new_index)
                backoff = cfg.backoff_base
                continue

            log.info("Замечено изменение в KV: индекс %d -> %d, пересогласовываем сервисы ...",
                     last_index, new_index)
            try:
                desired = parse_desired_state(value, cfg) if value is not None else {}
            except InvalidDesiredState as error:
                log.error(
                    "Некорректный desired config: %s. Существующие сервисы и checks не изменяются.",
                    error,
                )
                # Ждём следующего изменения ключа, не создавая busy-loop.
                last_index = new_index
                backoff = cfg.backoff_base
                continue
            if value is None:
                log.warning("Файл конфигурации %s был удалён. Дерегистрируем все связанные сервисы", cfg.consul_kv_path)
            if reconcile(consul, desired):
                active_checks.replace(desired)
                last_index = new_index
                backoff = cfg.backoff_base
            else:
                # last_index не двигаем -- следующая итерация повторит reconcile.
                # При index < real_index Consul вернёт ответ сразу, без блокировки,
                # но shutdown.sleep(backoff) защищает от спама агентом.
                log.warning("Reconcile завершился с ошибками, индекс не сдвигаем (повтор через %.1fс)",
                            backoff)
                shutdown.sleep(backoff)
                backoff = min(backoff * 2, cfg.backoff_cap)

        except requests.exceptions.ReadTimeout:
            # На стороне клиента отвал по таймауту, пока сервер удерживал запрос на длительное ожидание ответа
            # Безопасно перезапустить, last_index не изменять
            if shutdown.stop:
                break
            log.debug("Blocking-query отвалилась по таймауту. Переподключаемся")
            backoff = cfg.backoff_base
        except KVUnavailable as e:
            if shutdown.stop:
                break
            now = time.monotonic()
            if outage_started is None:
                outage_started = now
            consecutive_failures += 1
            log.error(
                "Consul KV недоступен: %s (попытка=%d, index=%d, повтор через %.1fс)",
                e,
                consecutive_failures,
                last_index,
                backoff,
            )
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
        except requests.RequestException as e:
            if shutdown.stop:
                break
            log.error("Ошибка с Consul API: %s (повтор через %.1fс)", e, backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
        except Exception as e:  # noqa: BLE001 -- main loop must flow
            if shutdown.stop:
                break
            log.exception("Неожиданная ошибка в цикле мониторинга: %s (повтор через %.1fс)",
                          e, backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)

    active_checks.stop()
    log.info("Shutdown выполнен")
    return 0

if __name__ == "__main__":
    sys.exit(main())
