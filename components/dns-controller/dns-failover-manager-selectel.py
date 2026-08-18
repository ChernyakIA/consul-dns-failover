#!/usr/bin/env python3
"""
Selectel DNS-Manager script. Запускается Consul-Template'ом при изменениях в статусе Consul-сервисов.
Управляет только А-записями.

1. Читает json-файл из template-service.tpl
2. Группирует записи по sel_zone_id и для каждой зоны один раз запрашивает rrset-индекс.
3. Сохраняет DNS при недостаточном числе observers (`unknown`).
4. При известном состоянии выбирает IP с числом site confirmations >= quorum;
   если таких нет, применяет on_all_fail: keep/remove/fallback.
5. Значение для CONSUL_HTTP_ADDR -- URL Consul API берётся из template selectel.hcl.

Список актуальных URL: https://docs.selectel.ru/api/urls/

Переменные:
  Обязательные:
    SEL_ACCOUNT_ID                  Номер аккаунта == договора
    SEL_SERVICE_USER                Имя сервисного пользователя
    SEL_SERVICE_PASS                Пасс сервисного пользователя
    SEL_PROJECT_NAME                Имя проекта в кот. упр. DNS-зоны
    DNS_PROVIDER_NAME               Имя провайдера (по умолчанию selecteldns)
    CONSUL_GC_PATH                  путь в Consul KV где будет хранится текущее состояние

  Опционально:
    LOG_LEVEL                       уровень логирования (по умолчанию INFO)
    SEL_AUTH_PROJECT_TOKEN_URL      по умолчанию https://cloud.api.selcloud.ru/identity/v3/auth/tokens.
                                    Док: https://docs.selectel.ru/api/authorization/#get-iam-token-project-scoped
    SEL_DNS_API_BASE                API DNS v2 (по умолчанию https://api.selectel.ru/domains/v2)
    SEL_LIST_RECORDS_LIMIT          кол-во запрашиваемых записей для пагинации (по умолчанию 40)
    HTTP_CONNECT_TIMEOUT            таймаут подключения, по умолчанию 5 секунд
    HTTP_READ_TIMEOUT               таймаут ожидания ответа, по умолчанию HTTP_TIMEOUT или 15 секунд
    HTTP_RETRY_TOTAL                число повторов безопасных GET-запросов, по умолчанию 2
    CONSUL_HTTP_TOKEN               ACL-токен Consul (если ACL включены)
"""
from __future__ import annotations

import os
import sys
import json
import logging
import base64
import requests
import yaml

from datetime import datetime
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# --------------------------------------------------------------------------- #
# Логирование                                                                 #
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("dns-manager-selectel")

# --------------------------------------------------------------------------- #
# Конфигурация                                                                #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Config:
    account_id:         str
    service_user:       str
    service_pass:       str
    project_name:       str
    consul_gc_path:     str
    auth_url:           str
    dns_api_base:       str
    page_limit:         int
    http_connect_timeout: int
    http_read_timeout:  int
    http_retry_total:   int
    consul_addr:        str
    consul_token:       Optional[str]
    consul_cacert:      Optional[str]
    consul_config_path: str
    dns_provider_name:  str

    @staticmethod
    def from_env() -> "Config":
        # Проверка обязательных переменных окружения
        required_envs = [
            "SEL_ACCOUNT_ID",
            "SEL_SERVICE_USER",
            "SEL_SERVICE_PASS",
            "SEL_PROJECT_NAME",
            "CONSUL_GC_PATH"
        ]
        missing_envs = [var for var in required_envs if var not in os.environ]
        if missing_envs:
            log.error("Отсутствуют обязательные переменные окружения: %s", ", ".join(missing_envs))
            sys.exit(1)

        consul_addr = os.environ["CONSUL_HTTP_ADDR"].rstrip("/")
        if not consul_addr.startswith(("http://", "https://")):
            consul_http_ssl = os.environ.get("CONSUL_HTTP_SSL", "true").strip().lower()
            scheme = "https" if consul_http_ssl in ("1", "true", "yes", "on") else "http"
            consul_addr = f"{scheme}://{consul_addr}"

        return Config(
            account_id   = os.environ["SEL_ACCOUNT_ID"],
            service_user = os.environ["SEL_SERVICE_USER"],
            service_pass = os.environ["SEL_SERVICE_PASS"],
            project_name = os.environ["SEL_PROJECT_NAME"],
            consul_gc_path = os.environ["CONSUL_GC_PATH"],
            auth_url     = os.environ.get(
                "SEL_AUTH_PROJECT_TOKEN_URL", "https://cloud.api.selcloud.ru/identity/v3/auth/tokens",
            ),
            dns_api_base = os.environ.get(
                "SEL_DNS_API_BASE", "https://api.selectel.ru/domains/v2",
            ).rstrip("/"),
            page_limit   = int(os.environ.get("SEL_LIST_RECORDS_LIMIT", "40")),
            http_connect_timeout = int(os.environ.get("HTTP_CONNECT_TIMEOUT", "5")),
            http_read_timeout = int(os.environ.get("HTTP_READ_TIMEOUT", os.environ.get("HTTP_TIMEOUT", "15"))),
            http_retry_total = int(os.environ.get("HTTP_RETRY_TOTAL", "2")),
            dns_provider_name = os.environ.get("DNS_PROVIDER_NAME", "selecteldns"),
            consul_addr  = consul_addr,
            consul_token = os.environ.get("CONSUL_HTTP_TOKEN") or None,
            consul_cacert = os.environ.get("CONSUL_CACERT") or None,
            consul_config_path = os.environ.get(
                "CONSUL_CONFIG_PATH", "dns-failover/dns-failover-monitoring-config.yml"
            ),
        )

# --------------------------------------------------------------------------- #
# Хранилище состояния в Consul KV                                              #
# --------------------------------------------------------------------------- #
class ConsulStateStore:
    """
    Сохраняет актуальный список управляемых доменов провайдера в отдельный JSON в KV.
    Файл используется GC для выявления удаленных из предыдущей версии конфига записей.
    """

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        if cfg.consul_cacert:
            self.session.verify = cfg.consul_cacert
        if cfg.consul_token:
            self.session.headers["X-Consul-Token"] = cfg.consul_token

    def load_active_records(self) -> Tuple[List[Dict[str, Any]], str, bool]:
        """Грузит список зафиксированных под управлением FQDN и дату его коммита"""
        url = f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_gc_path}{self.cfg.dns_provider_name}-active-config"
        try:
            r = self.session.get(url, timeout=5)
            if r.status_code == 404:
                log.info("Реестр зафиксированных доменов пуст (первый запуск).")
                return [], "N/A (холодный старт)", True
            r.raise_for_status()

            raw_val = r.json()[0].get("Value")
            if not raw_val:
                return [], "N/A (пустой токен ключа)", True

            decoded = base64.b64decode(raw_val).decode("utf-8")
            parsed_data = json.loads(decoded)

            if isinstance(parsed_data, dict):
                records = parsed_data.get("records") or []
                updated_at = parsed_data.get("updated_at") or "Дата/время не указаны"
                return records, updated_at, True

            return [], "N/A (некорректный формат данных в KV)", False

        except Exception as e:
            log.warning("Не удалось прочитать GC registry: %s. GC и обновление registry запрещены.", e)
            return [], "N/A (ошибка чтения Consul API)", False

    def load_desired_records(self) -> Tuple[List[Dict[str, Any]], bool]:
        url = f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_config_path}"
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 404:
                log.error("Desired config %s отсутствует; GC запрещён", self.cfg.consul_config_path)
                return [], False
            response.raise_for_status()
            encoded = response.json()[0].get("Value")
            if not encoded:
                return [], False
            document = yaml.safe_load(base64.b64decode(encoded).decode("utf-8"))
            if not isinstance(document, dict) or not isinstance(document.get("zones"), list):
                raise ValueError("Desired config должен содержать zones как YAML-массив")

            records: List[Dict[str, Any]] = []
            seen: set[str] = set()
            for zone_index, zone in enumerate(document["zones"]):
                if not isinstance(zone, dict):
                    raise ValueError(f"zones[{zone_index}] должен быть объектом")
                provider = zone.get("dns_provider")
                zone_name = zone.get("zone_name")
                if not provider or not zone_name:
                    raise ValueError(f"zones[{zone_index}] требует dns_provider и zone_name")
                if provider != self.cfg.dns_provider_name:
                    continue
                zone_id = zone.get("sel_zone_id")
                if not zone_id:
                    raise ValueError(f"zones[{zone_index}] требует sel_zone_id")
                zone_records = zone.get("records")
                if not isinstance(zone_records, list):
                    raise ValueError(f"zones[{zone_index}].records должен быть массивом")
                for record_index, record in enumerate(zone_records):
                    if not isinstance(record, dict) or record.get("name") is None:
                        raise ValueError(f"zones[{zone_index}].records[{record_index}] требует name")
                    fqdn = make_fqdn(str(record["name"]), str(zone_name)).lower()
                    if fqdn in seen:
                        raise ValueError(f"Дубликат managed record {fqdn}")
                    seen.add(fqdn)
                    records.append({
                        "fqdn": fqdn,
                        "zone": str(zone_name),
                        "sel_zone_id": str(zone_id),
                        "service_name": None,
                    })
            return records, True
        except (requests.RequestException, ValueError, KeyError, TypeError, IndexError, yaml.YAMLError) as error:
            log.error("Не удалось валидировать desired config; GC запрещён: %s", error)
            return [], False

    def save_active_records(self, state_records: List[Dict[str, Any]]) -> bool:
        """Сохраняет managed registry и явно сообщает об успехе записи."""
        url = f"{self.cfg.consul_addr}/v1/kv/{self.cfg.consul_gc_path}{self.cfg.dns_provider_name}-active-config"
        now_str = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        payload_dict = {
            "updated_at": now_str,
            "records": state_records,
        }
        try:
            payload = json.dumps(payload_dict, indent=2, ensure_ascii=False)
            response = self.session.put(url, data=payload, timeout=5)
            response.raise_for_status()
            log.warning("Реестр активных доменов обновлён в Consul KV. От %s", now_str)
            return True
        except Exception as error:
            log.error("Ошибка сохранения состояния в Consul KV: %s", error)
            return False


# --------------------------------------------------------------------------- #
# Selectel API                                                                #
# --------------------------------------------------------------------------- #
def get_iam_token(cfg: Config) -> str:
    """
    IAM project-scoped токен. Атоматические повторы запросов при сетевых сбоях.
    Док: https://docs.selectel.ru/api/authorization/#get-iam-token-project-scoped
    """
    payload = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": cfg.service_user,
                        "domain": {"name": cfg.account_id},
                        "password": cfg.service_pass,
                    }
                },
            },
            "scope": {
                "project": {
                    "name": cfg.project_name,
                    "domain": {"name": cfg.account_id},
                }
            },
        }
    }

    # Настройка повторов при ошибках DNS, таймаутах и 5##-тых
    # https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=[500, 502, 503, 504],
        raise_on_status=False,
        connect=3,
        read=3
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    log.info("Запрашиваю IAM-токен Selectel ...")
    try:
        r = session.post(
            cfg.auth_url,
            json=payload,
            timeout=(cfg.http_connect_timeout, cfg.http_read_timeout),
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        # Логируем ошибку вместо Traceback и выходим
        log.error("Ошибка при авторизации в Selectel: %s", e)
        raise SystemExit(1) from e
    tok = r.headers.get("X-Subject-Token")
    if not tok:
        raise RuntimeError("Selectel auth: X-Subject-Token не вернулся")
    return tok

class SelectelDNS:
    """Работа с DNS API v2."""

    def __init__(self, cfg: Config, token: str):
        self.cfg = cfg
        self.s = requests.Session()
        self.s.headers.update({
            "X-Auth-Token": token,
            "Content-Type": "application/json",
        })
        # Повторяем только безопасные GET-запросы. Автоматические повторы POST/PATCH/DELETE
        # могут повторить уже применённое изменение DNS.
        retries = Retry(
            total=cfg.http_retry_total,
            connect=cfg.http_retry_total,
            read=cfg.http_retry_total,
            status=cfg.http_retry_total,
            allowed_methods=frozenset({"GET"}),
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=1.5,
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        self.s.mount("https://", HTTPAdapter(max_retries=retries))

    @property
    def timeout(self) -> Tuple[int, int]:
        return self.cfg.http_connect_timeout, self.cfg.http_read_timeout

    def _zone_url(self, zone_id: str) -> str:
        return f"{self.cfg.dns_api_base}/zones/{zone_id}"

    def _check(self, r: requests.Response, action: str) -> None:
        if r.status_code >= 400:
            body = (r.text or "").strip().replace("\n", " ")[:300]
            if r.status_code in (401, 403):
                explanation = "проверь IAM-токен, project scope и права сервисного пользователя на DNS-зону"
            elif r.status_code == 404:
                explanation = "проверь sel_zone_id и наличие зоны в проекте SEL_PROJECT_NAME"
            elif r.status_code == 429:
                explanation = "Selectel ограничил частоту запросов; проверь частоту reconcile и Retry-After"
            elif r.status_code >= 500:
                explanation = "проверь состояние DNS API Selectel (https://selectel.live/status_pages/selectel/) и повтори запрос позднее"
            else:
                explanation = "смотри HTTP-ответ, проверь тело ответа и параметры запроса"
            raise RuntimeError(
                f"Selectel DNS API: операция {action} получила HTTP-ответ {r.status_code} -- {explanation}. Ответ API: {body or '<пусто>'}"
            )

    def _network_error(self, error: requests.RequestException, zone_id: str,
                       offset: int, attempts: int) -> RuntimeError:
        """Добавляет к исходной сетевой ошибке контекст запроса."""
        endpoint = f"{self._zone_url(zone_id)}/rrset"
        return RuntimeError(
            f"Selectel DNS API: запрос не выполнен; zone={zone_id}, offset={offset}, endpoint={endpoint},"
            f"попыток={attempts} (connect timeout={self.cfg.http_connect_timeout}s, read timeout={self.cfg.http_read_timeout}s)."
            f"Ошибка: {type(error).__name__}: {error}. DNS-изменения для этой зоны не выполняются, стейт в Consul KV не будет обновлён.",
        )

    def list_rrsets(self, zone_id: str) -> Dict[Tuple[str, str], Dict[str, Any]]:
        """Индекс {(name_lower_no_dot, type): rrset} с учётом пагинации."""
        idx: Dict[Tuple[str, str], Dict[str, Any]] = {}
        offset = 0
        url = f"{self._zone_url(zone_id)}/rrset"
        while True:
            attempts = self.cfg.http_retry_total + 1
            log.info(
                "Читаю RRsets зоны %s: offset=%s, до %s попыток, timeout connect=%ss/read=%ss",
                zone_id,
                offset,
                attempts,
                self.cfg.http_connect_timeout,
                self.cfg.http_read_timeout,
            )
            try:
                r = self.s.get(
                    url,
                    params={"limit": self.cfg.page_limit, "offset": offset},
                    timeout=self.timeout,
                )
            except requests.RequestException as error:
                raise self._network_error(error, zone_id, offset, attempts) from error
            self._check(r, f"LIST rrset zone={zone_id}")
            data = r.json()
            results = data.get("result", []) or []
            for rs in results:
                name = (rs.get("name") or "").rstrip(".").lower()
                rtype = rs.get("type") or ""
                idx[(name, rtype)] = rs
            next_offset = data.get("next_offset", 0) or 0
            if not next_offset or len(results) < self.cfg.page_limit:
                break
            offset = next_offset
        return idx

    def create(self, zone_id: str, fqdn: str, rtype: str,
               ttl: int, ips: List[str]) -> None:
        payload = {
            "name": fqdn.rstrip(".") + ".",  # FQDN должен должен быть с точкой в конце
            "type": rtype,
            "ttl": int(ttl),
            "records": [{"content": ip, "disabled": False} for ip in ips],
        }
        r = self.s.post(f"{self._zone_url(zone_id)}/rrset", json=payload, timeout=self.timeout)
        self._check(r, f"CREATE {fqdn} {rtype}")

    def patch(self, zone_id: str, rrset_id: str,
              ttl: int, ips: List[str]) -> None:
        payload = {
            "ttl":     int(ttl),
            "records": [{"content": ip, "disabled": False} for ip in ips],
        }
        r = self.s.patch(f"{self._zone_url(zone_id)}/rrset/{rrset_id}", json=payload, timeout=self.timeout)
        self._check(r, f"PATCH rrset={rrset_id}")

    def delete(self, zone_id: str, rrset_id: str) -> None:
        r = self.s.delete(f"{self._zone_url(zone_id)}/rrset/{rrset_id}",
                          timeout=self.timeout)
        self._check(r, f"DELETE rrset={rrset_id}")

# --------------------------------------------------------------------------- #
# Логика принятия решения                                                     #
# --------------------------------------------------------------------------- #
def make_fqdn(record: str, zone: str) -> str:
    record = (record or "").strip(".")
    zone   = (zone   or "").strip(".")
    if not record or record == "@":
        return zone
    return f"{record}.{zone}"

def relative_record_name(fqdn: str, zone: str) -> str:
    """Remove exactly one trailing zone suffix from an FQDN."""
    normalized_fqdn = (fqdn or "").strip(".")
    normalized_zone = (zone or "").strip(".")
    if normalized_fqdn.lower() == normalized_zone.lower():
        return "@"
    suffix = f".{normalized_zone}"
    if normalized_zone and normalized_fqdn.lower().endswith(suffix.lower()):
        return normalized_fqdn[:-len(suffix)]
    return normalized_fqdn

def decide(item: Dict[str, Any]) -> Tuple[str, List[str]]:
    """
    Возвращает (action, ips). Варианты action: "set", "remove", "keep".
    Голоса считаются по уникальным sites, а не по числу Consul agents.
    """
    quorum      = int(item.get("quorum") or 1)
    minimum_observers = int(item.get("minimum_observers") or quorum)
    candidates  = item.get("candidates") or list((item.get("observations") or {}).keys())
    observations = item.get("observations") or {}
    confirms    = item.get("confirmations") or {}
    on_all_fail = (item.get("on_all_fail") or "keep").lower()
    fallback    = (item.get("fallback_ip") or "").strip()

    if any(int(observations.get(ip, 0)) < minimum_observers for ip in candidates):
        return "keep", []

    ips = sorted(ip for ip in candidates if int(confirms.get(ip, 0)) >= quorum)
    if ips:
        return "set", ips

    if on_all_fail == "remove":
        return "remove", []
    if on_all_fail == "fallback" and fallback:
        return "set", [fallback]
    return "keep", []

def reconcile_one(api: SelectelDNS,
                  item: Dict[str, Any],
                  zone_index: Dict[Tuple[str, str], Dict[str, Any]]) -> None:
    fqdn    = make_fqdn(item["record"], item["zone"])
    rtype   = "A"
    ttl     = int(item.get("ttl") or 60)
    svc     = item.get("service_name", fqdn)
    zone_id = item["sel_zone_id"]

    action, ips = decide(item)
    existing    = zone_index.get((fqdn.lower(), rtype))

    if action == "keep":
        log.info("[%s] %s %s: сохраняю (on_all_fail=keep)",
                 svc, fqdn, rtype)
        return

    if action == "remove":
        if existing:
            log.warning("[%s] %s %s: удаляю id=%s",
                     svc, fqdn, rtype, existing["id"])
            api.delete(zone_id, existing["id"])
        else:
            log.info("[%s] %s %s: уже отсутствует",
                     svc, fqdn, rtype)
        return

    # action == "set"
    # При пустом списке в патче Sel отдаст ошибку, обработаем тут и выведем в лог.
    if not ips:
        log.warning("[%s] %s %s: set с пустым списком IP -- пропускаю",
                    svc, fqdn, rtype)
        return

    # Если rrset нету
    if not existing:
        log.warning("[%s] %s %s: создаю запись с ttl=%s ips=%s",
                 svc, fqdn, rtype, ttl, ips)
        api.create(zone_id, fqdn, rtype, ttl, ips)
        return

    # Если rrset есть
    cur_ips = sorted(
        (r.get("content") or "")
        for r in (existing.get("records") or [])
        if not r.get("disabled")
    )
    cur_ttl = int(existing.get("ttl") or 0)

    if cur_ips == ips and cur_ttl == ttl:
        log.info("[%s] %s %s: уже имеет %s с ttl=%s -- пропускаю",
                 svc, fqdn, rtype, ips, ttl)
        return

    log.warning("[%s] %s %s: патчу ttl %s->%s и/или ips %s->%s",
             svc, fqdn, rtype, cur_ttl, ttl, cur_ips, ips)
    api.patch(zone_id, existing["id"], ttl, ips)

# --------------------------------------------------------------------------- #
# Главный скрипт                                                             #
# --------------------------------------------------------------------------- #
def load_items(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Ожидается JSON-массив верхнего уровня, а получил объект")
    return data

def main() -> int:
    if len(sys.argv) < 2:
        log.error("Использую: dns-failover-manager-selectel.py <state.json>")
        return 2

    src = sys.argv[1]
    log.info("Читаю состояние из %s", src)

    try:
        items = load_items(src)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        log.error("Не смог распарсить %s: %s", src, e)
        return 2

    cfg = Config.from_env()
    state_store = ConsulStateStore(cfg)

    previous_managed, last_updated_at, previous_known = state_store.load_active_records()
    log.info("Реестр зафиксированных доменов выгружен. Сравниваю со стейтом от: '%s'", last_updated_at)

    current_managed_list, desired_known = state_store.load_desired_records()
    previous_by_fqdn = {x["fqdn"]: x for x in previous_managed}
    current_by_fqdn = {x["fqdn"]: x for x in current_managed_list}

    # GC разрешён только когда и старый registry, и исходный desired config прочитаны успешно.
    orphans_fqdns = (
        set(previous_by_fqdn.keys()) - set(current_by_fqdn.keys())
        if previous_known and desired_known else set()
    )

    # Сортируем все целевые записи по зонам
    by_zone: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for it in items:
        zid = it.get("sel_zone_id")
        fqdn = make_fqdn(str(it.get("record", "")), str(it.get("zone", ""))).lower()
        # Consul Catalog меняется неатомарно относительно desired config. Не
        # применяем старый service и GC одной записи в рамках одного запуска.
        if zid and (not desired_known or fqdn in current_by_fqdn):
            by_zone[zid].append(it)

    # Добавляем сирот
    for orphan_fqdn in orphans_fqdns:
        orphan = previous_by_fqdn[orphan_fqdn]
        zid = orphan["sel_zone_id"]
        by_zone[zid].append({
            "record": relative_record_name(orphan_fqdn, orphan["zone"]),
            "zone": orphan["zone"],
            "sel_zone_id": zid,
            "status": "all_critical",
            "on_all_fail": "remove",  # Для удаленных форсируем remove
            "service_name": f"orphaned-{orphan_fqdn}"
        })

    if not by_zone:
        log.info("Нет активных записей и отсутствуют сироты для очистки. Работы нет.")
        if previous_known and desired_known:
            return 0 if state_store.save_active_records(current_managed_list) else 1
        return 0

    api = SelectelDNS(cfg, get_iam_token(cfg))
    errors = 0

    # Проведение согласования по каждой зоне
    for zone_id, zitems in by_zone.items():
        log.info("Зона %s: обслуживание %d записей (включая GC)", zone_id, len(zitems))
        try:
            index = api.list_rrsets(zone_id)
        except Exception as e:
            log.error("Не удалось прочитать список записей для зоны %s. %s", zone_id, e)
            errors += len(zitems)
            continue

        for it in zitems:
            try:
                reconcile_one(api, it, index)
            except Exception as e:
                log.error("[%s] ошибка применения изменений: %s", it.get("service_name"), e)
                errors += 1

    # Если транзакция прошла без ошибок -- коммитим новое состояние с актуальной датой в Consul KV
    if errors == 0:
        prev_sorted = sorted(previous_managed, key=lambda x: x.get("fqdn", ""))
        curr_sorted = sorted(current_managed_list, key=lambda x: x.get("fqdn", ""))

        # Сравниваем список доменов без учета timestamp
        if not previous_known or not desired_known:
            log.warning("GC или KV-конфиг неизвестен: GC не обновляется")
        elif prev_sorted == curr_sorted:
            log.info("Список обслуживаемых доменов не изменился. Пропускаю обновление реестра в Consul KV.")
        else:
            if not state_store.save_active_records(current_managed_list):
                return 1
        return 0
    else:
        log.error(
            "Синхронизация завершилась с ошибками (%d). "
            "Стейт в Consul KV не обновлён; это защитная остановка, а не ошибка Consul. Смотри логи.",
            errors,
        )
        return 1

if __name__ == "__main__":
    sys.exit(main())
