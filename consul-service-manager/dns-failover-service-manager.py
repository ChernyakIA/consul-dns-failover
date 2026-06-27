#!/usr/bin/env python3
"""
DNS-Failover daemon.

1. Читает yaml-файл `kv/dev-dns-failover/config` из Consul KV.
2. Фильтрует записи, относящиеся только к текущему SITE (Имени инстанса)
3. Регистрирует, обновляет и удаляет health-checks в локальном Consul-агенте

Переменные:
    SITE                    имя демона (обязательно)
    NODE_NAME               имя хоста. На случай нескольких демонов в HA
    SERVICE_NAME_PREFIX     префикс имени сервисов
    CONSUL_ADDR             урл агента (по умолчанию: http://127.0.0.1:8500)
    CONSUL_HTTP_TOKEN       ACL-токен Consul (если ACL включены)
    CONSUL_KV_PATH          путь к yaml-файлу-конфигу в Consul хранилище
    BLOCKING_WAIT           время на блокировку очереди (по умолчанию 5м)
    HTTP_TIMEOUT_BLOCKING   HTTP-таймаут для blocking-query (по умолчанию: 330с)
    ALLOW_EMPTY_BOOTSTRAP   можно ли сносить managed-сервисы при пустом конфиге на холодном старте (по умолчанию: false)
    LOG_LEVEL               уровень логирования (по умолчанию INFO)
    MANAGED_TAG             тег для регистрируемых сервисов

Consul-агент должен запускаться с опцией `enable_local_script_checks = true`, иначе скриптовые проверки скрытно не будут работать.
"""
from __future__ import annotations

import base64
import logging
import os
import signal
import sys
import time
import requests
import yaml
import hashlib
import json
import re

from dataclasses import dataclass, field
from types import FrameType
from typing import Any, Dict, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# Конфигурация                                                                #
# --------------------------------------------------------------------------- #
# SlugHelper для zone_name
_SLUG_RE = re.compile(r"[^a-zA-Z0-9_-]+")


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
    consul_kv_path: str
    blocking_wait: str
    managed_tag: str
    http_timeout_blocking: int
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
        
        scope_tag = f"daemon-site-{site}-node-{node_name}"
        consul_kv_path = os.environ.get("CONSUL_KV_PATH")
        if not consul_kv_path:
            raise KeyError("Определите переменную окружения 'CONSUL_KV_PATH'.")
        
        return Config(
            site=site,
            node_name=node_name,
            scope_tag=scope_tag,
            service_name_prefix=os.environ.get("SERVICE_NAME_PREFIX", "dev-dns-failover"),
            consul_addr=os.environ.get("CONSUL_ADDR", "http://127.0.0.1:8500").rstrip("/"),
            consul_http_token=os.environ.get("CONSUL_HTTP_TOKEN") or None,
            consul_kv_path=consul_kv_path,
            blocking_wait=os.environ.get("BLOCKING_WAIT", "5m"),
            managed_tag=os.environ.get("MANAGED_TAG", "dev-dns-failover-managed"),
            http_timeout_blocking=int(os.environ.get("HTTP_TIMEOUT_BLOCKING", "330")),
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
        log.info("Получил сигнал %d, корректно завершаю работу ...", signum)
        self.stop = True


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
    meta: Dict[str, str] = field(default_factory=dict)


    def config_hash(self) -> str:
        """SHA256 от всех полей, влияющих на поведение сервиса/чека."""
        material = {
            "name":    self.name,
            "address": self.address,
            "tags":    sorted(self.tags),
            "check":   self.check,
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

        interval = chk.get("interval", def_check.get("interval"))
        timeout  = chk.get("timeout", def_check.get("timeout"))
        if not interval:
            raise ValueError(f"check.interval/timeout не заданы для endpoint={ep!r}")
        dereg    = chk.get("deregister_critical_after", def_check.get("deregister_critical_after"))
        kind     = chk["kind"].lower()

        base_check = {"Interval": interval, "Timeout": timeout}
        
        sbp  = chk.get("success_before_passing", def_check.get("success_before_passing"))
        fbw  = chk.get("failures_before_warning", def_check.get("failures_before_warning"))
        fbc  = chk.get("failures_before_critical", def_check.get("failures_before_critical"))
        
        if sbp: base_check["SuccessBeforePassing"]  = int(sbp)
        fbw_val = int(fbw) if fbw else None
        fbc_val = int(fbc) if fbc else None

        if fbw_val is not None:
            base_check["FailuresBeforeWarning"] = fbw_val

        if fbc_val is not None:
            if fbw_val is not None:
                # fbc в yaml-конфиге -- количество проверок после warning
                # Для Consul мы преобразуем его по формуле int(warning) + int(critical)
                consul_absolute_fbc = fbw_val + fbc_val
                base_check["FailuresBeforeCritical"] = consul_absolute_fbc
                
                log.debug(
                    "Для записи %s в конфиге выставлено проверок до warning=%d, добавляем кол-во critical=%d и передаем в Consul FailuresBeforeCritical=%d",
                    record, fbw_val, fbc_val, consul_absolute_fbc
                )
            else:
                # Если warning не задан, то fbc_val -- это число сбоев сразу до critical
                base_check["FailuresBeforeCritical"] = fbc_val

        # "0s" и пустую строку Consul понимает как "никогда не дерегистрировать"
        if dereg and dereg != "0s":
            base_check["DeregisterCriticalServiceAfter"] = dereg
        
        # --------------------------------------------------------------------------- #
        # Проверки                                                                    #
        # --------------------------------------------------------------------------- #
        if kind == "tcp":
            port = chk.get("port")
            check = {**base_check, "TCP": f"{target}:{port}"}

        elif kind == "icmp":
            check = {**base_check, "Args": ["ping", "-c", "1", "-W", "1", target]}

        elif kind == "smtp":
            port = chk.get("port", 25)
            timeout_sec = 5  # таймаут в сек для netcat
            if timeout:
                match = re.match(r"(\d+)", str(timeout))
                if match:
                    timeout_sec = int(match.group(1))
            shell_cmd = (
                f"out=$( (sleep 1; echo 'QUIT') | nc -w {timeout_sec} {target} {port} 2>&1 ); "
                f"echo \"$out\"; "
                f"echo \"$out\" | grep -q '^220'"
            )
            check = {**base_check, "Args": ["/bin/sh", "-c", shell_cmd]}

        elif kind == "http":
            if "url" in chk:
                url = chk["url"]
            else:
                scheme = chk.get("scheme", "http")
                port   = chk.get("port")
                path   = chk.get("path") or "/"
                if not path.startswith("/"):
                    path = "/" + path
                url = f"{scheme}://{target}:{port}{path}"
            check = {**base_check, "HTTP": url, "Method": chk.get("method", "GET"),}
            # опционально header, tls_skip_verify
            if "header" in chk:
                check["Header"] = chk["header"]
            if chk.get("tls_skip_verify"):
                check["TLSSkipVerify"] = True
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
            "on_all_fail": on_fail,
            "fallback_ip": fallback,
            "quorum": str(quorum),
            **provider_meta  # Динамические поля провайдеров == новые поля попадают сюда
        }
        return DesiredService(sid, name, ip, tuple(tags), check, kind, meta)


    def to_payload(self) -> Dict[str, Any]:
        meta_with_hash = {**self.meta, "config_hash": self.config_hash()}
        return {
            "ID":      self.service_id,
            "Name":    self.name,
            "Address": self.address,
            "Tags":    list(self.tags),
            "Meta":    meta_with_hash,
            "Check":   self.check,
        }


def _has_drift(current: Dict[str, Any], desired: DesiredService) -> bool:
    """
    True -> перегистрируем.

    Сравниваем config_hash из Meta. Если хэша нет (старый сервис, до апгрейда
    демона), то считаем drift и регистрируем заново, чтобы записать хэш.
    """
    current_hash = (current.get("Meta") or {}).get("config_hash")
    if not current_hash:
        log.info("У сервиса id=%s нет config_hash — миграция, регистрируем заново",
                 current.get("ID"))
        return True
    return current_hash != desired.config_hash()


def _slug(value: str) -> str:
    """
    Приводит строку к виду, безопасному для Consul: оставляем [A-Za-z0-9_-],
    всё остальное изменяем на '-'.
    Пример: 'dev-rezonit.ru' -> 'dev-rezonit-ru'.
    """
    return _SLUG_RE.sub("-", value).strip("-")

# --------------------------------------------------------------------------- #
# Consul HTTP-клиент                                                          #
# --------------------------------------------------------------------------- #
class KVUnavailable(Exception):
    """Consul KV временно недоступен (сеть/5xx). Reconcile не выполнять."""


def _raise_with_body(r: requests.Response, what: str) -> None:
    if r.status_code >= 400:
        body = (r.text or "").strip().replace("\n", " ")[:500]
        raise requests.HTTPError(
            f"{what}: HTTP {r.status_code} {r.reason} — {body}",
            response=r,
        )


class ConsulClient:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.base_url = cfg.consul_addr.rstrip("/")
        # Sessions повторно использует tcp-соединения
        self.session = requests.Session()
        # Стандартный заголовок ACL-токена Consul
        # Если ACL не включены, агент просто игнорирует заголовок
        if cfg.consul_http_token:
            self.session.headers["X-Consul-Token"] = cfg.consul_http_token
            log.info("Используем ACL-токен из CONSUL_HTTP_TOKEN (len=%d)", len(cfg.consul_http_token))
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
        }


    def register(self, payload: Dict[str, Any]) -> None:
        """Регистрация сервиса через агента"""
        # Регистрация через агента отличается от регистрации напрямую на сервере
        url = f"{self.base_url}/v1/agent/service/register"
        r = self.session.put(url, json=payload, params={"replace-existing-checks": "true"},
                             timeout=self.cfg.http_timeout_short)
        _raise_with_body(r, f"register id={payload.get('ID')}")

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
        log.error("Ошибка в YAML: %s. Предыдущее состояние осталось пустым.", e)
        return {}

    defaults = doc.get("defaults") or {}
    # Задаем ключевые константные поля схемы, чтобы отсечь их от метаданных провайдеров
    KNOWN_ZONE_KEYS = {"zone_name", "dns_provider", "records"}

    desired: Dict[str, DesiredService] = {}
    # Проходим по всем зонам в конифге
    for i, zone in enumerate(doc.get("zones", []) or []):
        zone_name = zone.get("zone_name")
        dns_provider = zone.get("dns_provider")

        if not zone_name or not dns_provider:
            log.error("В блоке #%d в файле конфигурации не указан zone_name или dns_provider. Пропуск всей зоны", i)
            continue

        # Всё, что не входит в KNOWN_ZONE_KEYS, объявляется параметром провайдера -- заносится в meta
        provider_meta: Dict[str, str] = {
            k: str(v)
            for k, v in zone.items()
            if k not in KNOWN_ZONE_KEYS and v is not None
        }

        for record in zone.get("records", []) or []:
            rec_name = record.get("name")
            if not rec_name:
                log.warning("zone=%s: запись без значения name. Пропускаем", zone_name)
                continue
            for ep in record.get("endpoints", []) or []:
                sites = ep.get("sites")
                # Если site в yaml-конфиге указан не этого демона, то пропускаем
                if not sites or cfg.site not in sites:
                    continue
                ip = ep.get("ip")
                check_proto = ep.get("check")
                if not ip or not check_proto:
                    log.warning("zone=%s record=%s: пропущен ip / check. Пропускаем %r",
                                zone_name, rec_name, ep)
                    continue
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
                    log.error("zone=%s record=%s endpoint=%r: ошибка парсинга (%s: %s) -- пропускаем",
                              zone_name, rec_name, ep, type(e).__name__, e)
                    continue
                if ds.service_id in desired:
                    log.warning("Дубликат service_id=%s, перезаписываем", ds.service_id)
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
            log.info("Зарегистрированный сервис id=%s name=%s address=%s check=%s",
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
            log.info("Дерегистрация устаревшего сервиса id=%s", sid)
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
    except Exception as e:
        log.error("Ошибка инициализации конфигурации окружения: %s", e)
        return 1
    
    log.info("Стартуем DNS-Failover Control Plane (consul=%s, kv=%s, wait=%s, allow_empty_bootstrap=%s)",
             cfg.consul_addr, cfg.consul_kv_path, cfg.blocking_wait, cfg.allow_empty_bootstrap)
    shutdown = Shutdown()
    consul = ConsulClient(cfg)

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
        desired = ({} if config_missing else parse_desired_state(value, cfg))

        if config_missing:
            log.warning("KV-файл %s отсутствует (HTTP 404).", cfg.consul_kv_path)
        elif not desired:
            log.warning("KV-файл %s прочитан, но желаемых сервисов для site=%s = 0.",
                        cfg.consul_kv_path, cfg.site)
        else:
            log.info("Конфиг прочитан (index=%d), желаемых сервисов для site=%s: %d",
                     new_index, cfg.site, len(desired))
            
        # Защита на холодном старте:
        # при пустом/удалённом конфиге не дерегистрируем существующие managed-сервисы,
        # а ждём появления валидного конфига. Снимается флагом ALLOW_EMPTY_BOOTSTRAP=true.
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

    while not shutdown.stop:
        try:
            value, new_index = consul.kv_read(cfg.consul_kv_path, index=last_index, wait=cfg.blocking_wait)
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
            desired = parse_desired_state(value, cfg) if value is not None else {}
            if value is None:
                log.warning("Файл конфигурации %s был удалён. Дерегистрируем все связанные сервисы", cfg.consul_kv_path)
            if reconcile(consul, desired):
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
            log.debug("Blocking-query отвалилась по таймауту. Переподключаемся")
            backoff = cfg.backoff_base
        except requests.RequestException as e:
            log.error("Ошибка с Consul API: %s (повтор через %.1fс)", e, backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)
        except Exception as e:  # noqa: BLE001 -- main loop must flow
            log.exception("Неожиданная ошибка в цикле мониторинга: %s (повтор через %.1fс)",
                          e, backoff)
            shutdown.sleep(backoff)
            backoff = min(backoff * 2, cfg.backoff_cap)

    log.info("Shutdown выполнен")
    return 0

if __name__ == "__main__":
    sys.exit(main())
