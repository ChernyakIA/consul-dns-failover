from __future__ import annotations

import json

import pytest

from conftest import load_module

ZONE_URL = "https://dns.example.com/dns/v1/zones/zone-1"


@pytest.fixture
def module():
    return load_module("test_yandex_dns", "components/dns-controller/dns-failover-manager-yandex.py")


def config(module, **overrides):
    values = dict(
        sa_key_file="/keys/authorized_key.json", consul_gc_path="dns-failover/gc/",
        iam_token_url="https://iam.example.com/iam/v1/tokens",
        dns_api_base="https://dns.example.com/dns/v1",
        operation_api_base="https://operation.example.com",
        page_limit=2, operation_timeout=5, http_connect_timeout=5, http_read_timeout=15,
        http_retry_total=2, consul_addr="https://consul.example.com", consul_token=None,
        consul_cacert=None, consul_config_path="dns-failover/config.yml",
        dns_provider_name="yandexdns",
    )
    values.update(overrides)
    return module.Config(**values)


class Response:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self):
        return self.payload


class Session:
    """Replays queued responses and records every request."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        return self.responses.pop(0)


def client(module, *responses, **overrides):
    api = module.YandexDNS(config(module, **overrides), "token")
    assert api.s.headers["Authorization"] == "Bearer token"
    api.s = Session(*responses)
    return api


def test_list_follows_pages_and_indexes_names_without_trailing_dot(module):
    api = client(
        module,
        Response({
            "recordSets": [{"name": "App.Example.com.", "type": "A", "ttl": "60", "data": ["192.0.2.10"]}],
            "nextPageToken": "page-2",
        }),
        Response({"recordSets": [{"name": "example.com.", "type": "A", "ttl": "300", "data": ["192.0.2.20"]}]}),
    )

    index = api.list_record_sets("zone-1")

    assert set(index) == {("app.example.com", "A"), ("example.com", "A")}
    first, second = api.s.requests
    assert first[:2] == ("GET", f"{ZONE_URL}:listRecordSets")
    assert first[2]["params"] == {"pageSize": 2, "filter": 'type="A"'}
    assert second[2]["params"] == {"pageSize": 2, "filter": 'type="A"', "pageToken": "page-2"}


def test_create_is_strict_and_sends_fqdn_with_string_ttl(module):
    api = client(module, Response({"id": "op-1", "done": True}))

    api.add_record_set("zone-1", "app.example.com", 60, ["192.0.2.10"])

    method, url, kwargs = api.s.requests[0]
    assert (method, url) == ("POST", f"{ZONE_URL}:updateRecordSets")
    assert kwargs["json"] == {
        "additions": [{"name": "app.example.com.", "type": "A", "ttl": "60", "data": ["192.0.2.10"]}]
    }


def test_replace_uses_upsert_replacements(module):
    api = client(module, Response({"id": "op-1", "done": True}))

    api.replace_record_set("zone-1", "app.example.com.", 120, ["192.0.2.10", "192.0.2.20"])

    method, url, kwargs = api.s.requests[0]
    assert (method, url) == ("POST", f"{ZONE_URL}:upsertRecordSets")
    assert kwargs["json"] == {"replacements": [
        {"name": "app.example.com.", "type": "A", "ttl": "120", "data": ["192.0.2.10", "192.0.2.20"]}
    ]}


def test_delete_sends_the_listed_record_set_unchanged(module):
    listed = {"name": "app.example.com.", "type": "A", "ttl": "60", "data": ["192.0.2.10"], "description": "x"}
    api = client(module, Response({"id": "op-1", "done": True}))

    api.delete_record_set("zone-1", listed)

    method, url, kwargs = api.s.requests[0]
    assert (method, url) == ("POST", f"{ZONE_URL}:updateRecordSets")
    assert kwargs["json"] == {"deletions": [listed]}


def test_change_waits_for_the_operation_to_complete(module, monkeypatch):
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    api = client(
        module,
        Response({"id": "op-1", "done": False}),
        Response({"id": "op-1", "done": False}),
        Response({"id": "op-1", "done": True, "response": {}}),
    )

    api.add_record_set("zone-1", "app.example.com", 60, ["192.0.2.10"])

    assert [request[:2] for request in api.s.requests[1:]] == [
        ("GET", "https://operation.example.com/operations/op-1"),
        ("GET", "https://operation.example.com/operations/op-1"),
    ]


def test_failed_operation_is_reported(module, monkeypatch):
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    api = client(
        module,
        Response({"id": "op-1", "done": False}),
        Response({"id": "op-1", "done": True, "error": {"code": 9, "message": "record set already exists"}}),
    )

    with pytest.raises(RuntimeError, match="Yandex Cloud DNS API: .*record set already exists"):
        api.add_record_set("zone-1", "app.example.com", 60, ["192.0.2.10"])


def test_operation_that_never_completes_times_out(module, monkeypatch):
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    api = client(module, Response({"id": "op-1", "done": False}), operation_timeout=0)

    with pytest.raises(RuntimeError, match="did not complete within 0s"):
        api.add_record_set("zone-1", "app.example.com", 60, ["192.0.2.10"])


def test_http_error_explains_permissions(module):
    api = client(module, Response({"message": "Permission denied"}, status_code=403))

    with pytest.raises(RuntimeError, match="Yandex Cloud DNS API: .*HTTP response 403 .*dns.editor"):
        api.list_record_sets("zone-1")


def test_verification_compares_ttl_and_addresses(module):
    item = {"record": "app", "zone": "example.com", "yc_zone_id": "zone-1", "ttl": "60"}
    index = {("app.example.com", "A"): {"name": "app.example.com.", "ttl": "60", "data": ["192.0.2.20", "192.0.2.10"]}}
    common = load_module("test_yandex_common", "components/dns-controller/dns_controller_common.py")

    matching = common.Decision("set", ["192.0.2.10", "192.0.2.20"], "")
    different = common.Decision("set", ["192.0.2.10"], "")
    removal = common.Decision("remove", [], "")

    assert module.yandex_verified(index, item, matching) == (True, False)
    assert module.yandex_verified(index, item, different) == (False, False)
    assert module.yandex_verified(index, item, removal) == (False, False)
    assert module.yandex_verified({}, item, removal) == (False, True)


def test_jwt_is_signed_with_ps256_for_the_iam_audience(module):
    jwt = pytest.importorskip("jwt")
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ).decode()
    key = {
        "id": "key-id",
        "service_account_id": "sa-id",
        # Yandex Cloud prefixes the PEM block with a comment line.
        "private_key": "PLEASE DO NOT REMOVE THIS LINE! Yandex.Cloud SA Key ID <key-id>\n" + pem,
    }
    audience = "https://iam.api.cloud.yandex.net/iam/v1/tokens"

    token = module.build_jwt(key, audience, now=1_800_000_000)

    assert jwt.get_unverified_header(token) == {"typ": "JWT", "alg": "PS256", "kid": "key-id"}
    claims = jwt.decode(
        token, private_key.public_key(), algorithms=["PS256"], audience=audience,
        options={"verify_exp": False, "verify_iat": False},
    )
    assert claims["iss"] == "sa-id"
    assert claims["iat"] == 1_800_000_000
    assert 0 < claims["exp"] - claims["iat"] <= 3600


def test_incomplete_authorized_key_is_rejected(module):
    with pytest.raises(ValueError, match="service_account_id"):
        module.build_jwt({"id": "key-id", "private_key": "-----BEGIN PRIVATE KEY-----"}, "aud")


def test_unreadable_authorized_key_stops_without_traceback(module, tmp_path, caplog):
    cfg = config(module, sa_key_file=str(tmp_path / "missing.json"))

    with pytest.raises(SystemExit):
        module.get_iam_token(cfg)

    assert "Yandex Cloud authentication failed" in caplog.text
