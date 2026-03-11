"""tests/test_secrets_manager.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from secrets_manager import SecretsManagerClient


def get_client():
    return SecretsManagerClient(use_mock=True)


def test_list_secrets_returns_list():
    assert isinstance(get_client().list_secrets(), list)
    assert len(get_client().list_secrets()) > 0


def test_get_existing_secret():
    assert get_client().get_secret("prod/db/password") is not None


def test_get_nonexistent_secret_returns_none():
    assert get_client().get_secret("does/not/exist") is None


def test_create_secret_adds_to_store():
    client = get_client()
    client.create_secret("test/new/secret", "testvalue123")
    assert "test/new/secret" in client.list_secrets()


def test_create_duplicate_secret_fails():
    client = get_client()
    result = client.create_secret("prod/db/password", "duplicate")
    assert result is False


def test_update_existing_secret():
    client = get_client()
    result = client.update_secret("prod/db/password", "newpassword!")
    assert result is True
    assert client.get_secret("prod/db/password") == "newpassword!"


def test_update_nonexistent_secret_fails():
    result = get_client().update_secret("fake/secret", "value")
    assert result is False


def test_delete_secret_removes_from_store():
    client = get_client()
    client.create_secret("temp/secret", "temp")
    client.delete_secret("temp/secret")
    assert "temp/secret" not in client.list_secrets()


def test_audit_log_records_operations():
    client = get_client()
    client.get_secret("prod/db/password")
    client.list_secrets()
    assert len(client._audit_log) >= 2


def test_audit_rotation_returns_findings():
    findings = get_client().audit_rotation()
    assert isinstance(findings, list)
    assert len(findings) > 0
    for f in findings:
        assert "secret" in f and "status" in f and "severity" in f
