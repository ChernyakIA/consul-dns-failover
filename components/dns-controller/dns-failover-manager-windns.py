#!/usr/bin/env python3
"""
Windows DNS-Manager script. Запускается Consul-Template'ом при изменениях в статусе Consul-сервисов.
Управляет только А-записями в Microsoft DNS через SSH + PowerShell.

1. Читает json-файл из template-service.tpl
2. Сохраняет DNS при недостаточном числе observers (`unknown`).
3. При известном состоянии выбирает IP с числом site confirmations >= quorum;
   если таких нет, применяет on_all_fail: keep/remove/fallback.
4. Значение для CONSUL_HTTP_ADDR -- URL Consul API берётся из template windns.hcl.

Переменные:
  Обязательные:
    WIN_SSH_HOST                            Куда выполняем SSH (Jump или DC)
    WIN_SSH_USER                            Пользователь SSH (например, 'EXAMPLE\\dns-failover-mgmt')
    WIN_SSH_KEY_PATH / WIN_SSH_PASSWORD     Задай ключ ИЛИ пароль для авторизации. Ключ приоритетнее
    WIN_SSH_KNOWN_HOSTS                     Путь к known_hosts для обязательной проверки host key
    DNS_PROVIDER_NAME                       Имя провайдера (по умолчанию windns)
    CONSUL_GC_PATH                          путь в Consul KV, где будет храниться текущее состояние

  Опциональные:
    LOG_LEVEL                               уровень логирования (по умолчанию INFO)
    WIN_SSH_PORT                            по умолчанию 22
    SSH_CONNECT_TIMEOUT                     по умолчанию 10 сек
    SSH_TIMEOUT                             общий таймаут команды (по умолчанию 60)
    CONSUL_HTTP_TOKEN                       ACL-токен Consul (если ACL включены)
"""
from __future__ import annotations

import os
import sys
import json
import base64
import requests
import yaml
import logging
import subprocess
from datetime import datetime
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

# --------------------------------------------------------------------------- #
# Логирование                                                                 #
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("dns-manager-windns")

# --------------------------------------------------------------------------- #
# Конфиг                                                                      #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Config:
    ssh_host:           str
    ssh_user:           str
    consul_gc_path:     str
    ssh_port:           int
    ssh_password:       Optional[str]
    ssh_key_path:       Optional[str]
    ssh_known_hosts:    Optional[str]
    insecure_skip_host_key_check: bool
    connect_timeout:    int
    cmd_timeout:        int
    consul_addr:        str
    consul_token:       Optional[str]
    consul_cacert:      Optional[str]
    consul_config_path: str
    dns_provider_name:  str


    @staticmethod
    def from_env() -> "Config":
        # Проверка обязательных переменных окружения
        required_envs = ["WIN_SSH_HOST", "WIN_SSH_USER", "CONSUL_GC_PATH", "CONSUL_HTTP_ADDR"]
        missing_envs = [var for var in required_envs if var not in os.environ]
        if missing_envs:
            log.error("Отсутствуют обязательные переменные окружения: %s", ", ".join(missing_envs))
            sys.exit(1)

        password = os.environ.get("WIN_SSH_PASSWORD") or None
        key      = os.environ.get("WIN_SSH_KEY_PATH") or None

        if not password and not key:
            log.error("Необходимо задать WIN_SSH_PASSWORD или WIN_SSH_KEY_PATH")
            sys.exit(1)

        if password and key:
            log.warning("Заданы сразу оба параметра: WIN_SSH_KEY_PATH и WIN_SSH_PASSWORD. Использую SSH-ключ.")
            password = None

        ssh_known_hosts = os.environ.get("WIN_SSH_KNOWN_HOSTS") or None
        insecure_skip_host_key_check = os.environ.get(
            "WIN_SSH_INSECURE_SKIP_HOST_KEY_CHECK", "false"
        ).strip().lower() in ("1", "true", "yes", "on")
        if not ssh_known_hosts and not insecure_skip_host_key_check:
            log.error(
                "WIN_SSH_KNOWN_HOSTS обязателен. Только для временной миграции можно задать "
                "WIN_SSH_INSECURE_SKIP_HOST_KEY_CHECK=true"
            )
            sys.exit(1)

        consul_addr = os.environ["CONSUL_HTTP_ADDR"].rstrip("/")
        if not consul_addr.startswith(("http://", "https://")):
            consul_http_ssl = os.environ.get("CONSUL_HTTP_SSL", "true").strip().lower()
            scheme = "https" if consul_http_ssl in ("1", "true", "yes", "on") else "http"
            consul_addr = f"{scheme}://{consul_addr}"

        return Config(
            ssh_host        = os.environ["WIN_SSH_HOST"],
            ssh_user        = os.environ["WIN_SSH_USER"],
            consul_gc_path  = os.environ["CONSUL_GC_PATH"],
            consul_addr     = consul_addr,
            ssh_port        = int(os.environ.get("WIN_SSH_PORT", "22")),
            ssh_password    = password,
            ssh_key_path    = key,
            ssh_known_hosts   = ssh_known_hosts,
            insecure_skip_host_key_check = insecure_skip_host_key_check,
            connect_timeout = int(os.environ.get("SSH_CONNECT_TIMEOUT", "10")),
            cmd_timeout     = int(os.environ.get("SSH_TIMEOUT", "60")),
            dns_provider_name = os.environ.get("DNS_PROVIDER_NAME", "windns"),
            consul_token    = os.environ.get("CONSUL_HTTP_TOKEN") or None,
            consul_cacert   = os.environ.get("CONSUL_CACERT") or None,
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
                dns_server = zone.get("win_dns_server")
                if not dns_server:
                    raise ValueError(f"zones[{zone_index}] требует win_dns_server")
                zone_records = zone.get("records")
                if not isinstance(zone_records, list):
                    raise ValueError(f"zones[{zone_index}].records должен быть массивом")
                for record_index, record in enumerate(zone_records):
                    if not isinstance(record, dict) or record.get("name") is None:
                        raise ValueError(f"zones[{zone_index}].records[{record_index}] требует name")
                    name = ps_record_name(str(record["name"]))
                    fqdn = make_fqdn(name, str(zone_name))
                    if fqdn in seen:
                        raise ValueError(f"Дубликат managed record {fqdn}")
                    seen.add(fqdn)
                    records.append({
                        "fqdn": fqdn,
                        "record": name,
                        "zone": str(zone_name),
                        "win_dns_server": str(dns_server),
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
# SSH + PowerShell клиент                                                     #
# --------------------------------------------------------------------------- #
class WinDNS:
    """
    Каждый вызов -- одна короткая SSH-сессия + одна PowerShell-команда,
    переданная через -EncodedCommand (UTF-16LE base64).
    """


    def __init__(self, cfg: Config):
        self.cfg = cfg


    # Подготовка ssh и ps-запроса
    @staticmethod
    def _encode_ps(script: str) -> str:
        return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


    def _ssh_argv(self, ps_b64: str) -> List[str]:
        argv: List[str] = []
        if self.cfg.ssh_password:
            argv += ["sshpass", "-e"]

        argv += [
            "ssh",
            "-p", str(self.cfg.ssh_port),
            "-o", f"ConnectTimeout={self.cfg.connect_timeout}",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=3",
        ]
        if self.cfg.insecure_skip_host_key_check:
            log.warning("SSH host key verification отключена явным небезопасным флагом")
            argv += [
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
            ]
        else:
            argv += [
                "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={self.cfg.ssh_known_hosts}",
            ]
        argv += [
            "-o", "LogLevel=ERROR",
            "-o", "BatchMode=" + ("yes" if self.cfg.ssh_key_path else "no"),
        ]
        if self.cfg.ssh_key_path:
            argv += ["-i", self.cfg.ssh_key_path,
                     "-o", "IdentitiesOnly=yes",
                     "-o", "PreferredAuthentications=publickey"]
        else:
            argv += ["-o", "PreferredAuthentications=password",
                     "-o", "PubkeyAuthentication=no"]

        argv += [
            f"{self.cfg.ssh_user}@{self.cfg.ssh_host}",
            f"powershell -NoProfile -NonInteractive -EncodedCommand {ps_b64}",
        ]
        return argv


    def _run_ps(self, script: str, action: str) -> str:
        # 1) Глушим progress-stream, который и порождает "Preparing modules for first use"
        # 2) Любую необработанную ошибку упаковываем в чистый JSON с меткой PSERR:
        full = (
            "$ProgressPreference='SilentlyContinue';"
            "$ErrorActionPreference='Stop';"
            "try {\n" + script + "\n} catch {"
            "  $e = @{"
            "    message  = $_.Exception.Message;"
            "    type     = $_.Exception.GetType().FullName;"
            "    category = $_.CategoryInfo.ToString();"
            "    fqeid    = $_.FullyQualifiedErrorId"
            "  } | ConvertTo-Json -Compress -Depth 4;"
            "  [Console]::Error.WriteLine('PSERR:' + $e);"
            "  exit 1"
            "}"
        )
        argv = self._ssh_argv(self._encode_ps(full))
        env  = os.environ.copy()
        if self.cfg.ssh_password:
            env["SSHPASS"] = self.cfg.ssh_password

        try:
            cp = subprocess.run(argv, env=env, input="",
                                capture_output=True, text=True,
                                timeout=self.cfg.cmd_timeout)
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"{action}: SSH timeout ({e.timeout}s)") from None

        if cp.returncode != 0:
            err = cp.stderr or cp.stdout or ""
            # достаём наш JSON-маркер, если он есть
            if "PSERR:" in err:
                err = err.split("PSERR:", 1)[1].strip().splitlines()[0]
            else:
                err = err.strip().replace("\n", " ")
            raise RuntimeError(f"{action}: rc={cp.returncode}; {err}")
        return cp.stdout


    @staticmethod
    def _ps_str(s: str) -> str:
        """Безопасно вставить строку в одинарные PS-кавычки."""
        return "'" + s.replace("'", "''") + "'"

    # API
    def list_a_records(self, dns_server: str, zone: str) -> Dict[str, Dict[str, Any]]:
        """
        Индекс {hostname_lower: {"ttl": int, "ips": sorted[str]}}.
        Hostname возвращается относительный ('@' для apex).
        """
        script = (
            f"$rs = Get-DnsServerResourceRecord -ComputerName {self._ps_str(dns_server)} "
            f"-ZoneName {self._ps_str(zone)} -RRType A;"
            "$out = $rs | Group-Object HostName | ForEach-Object {"
            "  [PSCustomObject]@{"
            "    HostName = $_.Name;"
            "    TTL      = [int]($_.Group[0].TimeToLive.TotalSeconds);"
            "    IPs      = @($_.Group | ForEach-Object { $_.RecordData.IPv4Address.IPAddressToString })"
            "  }"
            "};"
            "ConvertTo-Json -Depth 5 -Compress -InputObject @($out)"
        )
        raw = self._run_ps(script, f"LIST {dns_server}/{zone}").strip()
        idx: Dict[str, Dict[str, Any]] = {}
        if not raw:
            return idx
        data = json.loads(raw)
        if isinstance(data, dict):  # PS отдаёт объект, а не массив, если элемент один
            data = [data]
        for rs in data:
            host = (rs.get("HostName") or "").lower()
            ips  = rs.get("IPs") or []
            if isinstance(ips, str):
                ips = [ips]
            idx[host] = {
                "ttl": int(rs.get("TTL") or 0),
                "ips": sorted(ips),
            }
        return idx


    def replace_a(self, dns_server: str, zone: str, name: str, ttl: int, ips: List[str]) -> None:
        """Атомарно (в одном PS-вызове): удалить все A для name, добавить ips."""
        adds = "\n".join(
            f"Add-DnsServerResourceRecordA "
            f"-ComputerName {self._ps_str(dns_server)} "
            f"-ZoneName {self._ps_str(zone)} "
            f"-Name {self._ps_str(name)} "
            f"-IPv4Address {self._ps_str(ip)} "
            f"-TimeToLive (New-TimeSpan -Seconds {int(ttl)});"
            for ip in ips
        )
        script = (
            "try {"
            "  Remove-DnsServerResourceRecord "
            f"   -ComputerName {self._ps_str(dns_server)}"
            f"   -ZoneName     {self._ps_str(zone)}"
            f"   -Name         {self._ps_str(name)}"
            "    -RRType A -Force"
            "} catch [Microsoft.Management.Infrastructure.CimException] {"
            # 9714 == DNS_ERROR_RECORD_DOES_NOT_EXIST -- нечего удалять, это норма
            "  if ($_.FullyQualifiedErrorId -notlike 'WIN32 9714*') { throw }"
            "}\n"
            f"{adds}"
        )
        self._run_ps(script, f"REPLACE {name}.{zone}@{dns_server}")


    def delete_a(self, dns_server: str, zone: str, name: str) -> None:
        script = (
            "try {"
            f"  Remove-DnsServerResourceRecord "
            f"    -ComputerName {self._ps_str(dns_server)}"
            f"    -ZoneName     {self._ps_str(zone)}"
            f"    -Name         {self._ps_str(name)}"
            "     -RRType A -Force"
            "} catch [Microsoft.Management.Infrastructure.CimException] {"
            "  if ($_.FullyQualifiedErrorId -notlike 'WIN32 9714*') { throw }"
            "}"
        )
        self._run_ps(script, f"DELETE {name}.{zone}@{dns_server}")

# --------------------------------------------------------------------------- #
# Логика принятия решения                                                     #
# --------------------------------------------------------------------------- #
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


def ps_record_name(record: str) -> str:
    """Имя записи в терминах WinDNS: пусто/@ -> '@'."""
    r = (record or "").strip().strip(".")
    return r if r else "@"


def make_fqdn(record: str, zone: str) -> str:
    name = ps_record_name(record)
    return zone.lower() if name == "@" else f"{name}.{zone}".lower()


def reconcile_one(api: WinDNS, item: Dict[str, Any], zone_index: Dict[str, Dict[str, Any]]) -> None:
    zone       = item["zone"]
    dns_server = item["win_dns_server"]
    name       = ps_record_name(item.get("record", ""))
    ttl        = int(item.get("ttl") or 60)
    svc        = item.get("service_name", f"{name}.{zone}")
    fqdn       = zone if name == "@" else f"{name}.{zone}"

    action, ips = decide(item)
    existing    = zone_index.get(name.lower())

    if action == "keep":
        log.warning("[%s] %s A: сохраняю (on_all_fail=keep)", svc, fqdn)
        return

    if action == "remove":
        if existing:
            log.warning("[%s] %s A: удаляю (текущее ips=%s)",
                     svc, fqdn, existing["ips"])
            api.delete_a(dns_server, zone, name)
        else:
            log.info("[%s] %s A: уже отсутствует", svc, fqdn)
        return

    # action == "set"
    if not ips:
        log.warning("[%s] %s A: set с пустым списком IP -- пропускаю",
                    svc, fqdn)
        return

    want = sorted(ips)
    if existing and existing["ips"] == want and existing["ttl"] == ttl:
        log.info("[%s] %s A: уже имеет %s ttl=%s -- пропускаю",
                 svc, fqdn, want, ttl)
        return

    if existing:
        log.warning("[%s] %s A: меняю ttl %s->%s, ips %s->%s",
                 svc, fqdn, existing["ttl"], ttl, existing["ips"], want)
    else:
        log.warning("[%s] %s A: создаю ttl=%s ips=%s",
                 svc, fqdn, ttl, want)
    api.replace_a(dns_server, zone, name, ttl, want)

# --------------------------------------------------------------------------- #
# Главный скрипт                                                              #
# --------------------------------------------------------------------------- #
def load_items(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Ожидается JSON-массив верхнего уровня, а получил объект")
    return data


def main() -> int:
    if len(sys.argv) < 2:
        log.error("Использую: dns-failover-manager-windns.py <state.json>")
        return 2

    src = sys.argv[1]
    log.info("Читаю состояние из %s", src)
    try:
        items = load_items(src)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        log.error("Не смог распарсить %s: %s", src, e)
        return 2

    try:
        cfg = Config.from_env()
    except (KeyError, RuntimeError) as e:
        log.error("Ошибка инициализации конфига: %s", e)
        return 2

    state_store = ConsulStateStore(cfg)

    # Считываем старый реестр из Consul KV
    previous_managed, last_updated_at, previous_known = state_store.load_active_records()
    log.info("Реестр зафиксированных доменов выгружен. Сравниваю со стейтом от: '%s'", last_updated_at)

    previous_by_fqdn = {x["fqdn"]: x for x in previous_managed}

    current_managed_list, desired_known = state_store.load_desired_records()
    current_by_fqdn = {x["fqdn"]: x for x in current_managed_list}

    # Осиротевшие записи для удаления
    orphans_fqdns = (
        set(previous_by_fqdn.keys()) - set(current_by_fqdn.keys())
        if previous_known and desired_known else set()
    )

    # Сортируем все целевые записи по парам (dns_server, zone)
    by_pair: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for it in items:
        srv  = it.get("win_dns_server")
        zone = it.get("zone")
        fqdn = make_fqdn(str(it.get("record", "")), str(zone or "")).lower()
        # Не исполняем одновременно устаревшее действие из Catalog и GC для
        # одной записи, если desired config уже удалил эту запись.
        if srv and zone and (not desired_known or fqdn in current_by_fqdn):
            by_pair[(srv, zone)].append(it)

    # Добавляем сирот
    for orphan_fqdn in orphans_fqdns:
        orphan = previous_by_fqdn[orphan_fqdn]
        srv = orphan["win_dns_server"]
        zone = orphan["zone"]
        record = orphan["record"]
        by_pair[(srv, zone)].append({
            "record": record,
            "zone": zone,
            "win_dns_server": srv,
            "status": "all_critical",
            "on_all_fail": "remove",  # Для удаленных форсируем remove
            "service_name": f"orphaned-{orphan_fqdn}"
        })

    if not by_pair:
        log.info("Нет активных записей и отсутствуют сироты для очистки. Завершаю работу.")
        if previous_known and desired_known:
            return 0 if state_store.save_active_records(current_managed_list) else 1
        return 0

    api = WinDNS(cfg)
    errors = 0

    # Проведение согласования по каждой паре
    for (dns_server, zone), zitems in by_pair.items():
        log.info("Сервер %s, зона %s: обслуживание %d записей (включая GC)", dns_server, zone, len(zitems))
        try:
            index = api.list_a_records(dns_server, zone)
        except Exception as e:
            log.error("Не удалось прочитать список записей для зоны %s, %s: %s", dns_server, zone, e)
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
            log.warning("Registry или desired config неизвестен: GC registry не обновляется")
        elif prev_sorted == curr_sorted:
            log.info("Список обслуживаемых доменов не изменился. Пропускаю обновление реестра в Consul KV.")
        else:
            if not state_store.save_active_records(current_managed_list):
                return 1
        return 0
    else:
        log.error("Синхронизация завершилась с ошибками (%d). Стейт в Consul KV не обновлён.", errors)
        return 1

if __name__ == "__main__":
    sys.exit(main())
