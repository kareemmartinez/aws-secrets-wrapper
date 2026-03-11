"""
secrets_manager.py
------------------
AWS Secrets Manager Wrapper
A Python module that abstracts AWS Secrets Manager operations:
get, create, update, rotate, and delete secrets.
Includes a CLI interface and a mock mode for safe local development.

Author: Kareem Martinez
"""

import os
import json
import datetime
import argparse


_MOCK_STORE = {
    "prod/db/password":    {"value": "s3cur3P@ssw0rd!", "created": "2024-01-01", "rotated": "2024-03-01"},
    "prod/api/stripe_key": {"value": "sk_live_XXXXXXXXXXXX", "created": "2024-01-15", "rotated": "2024-02-15"},
    "dev/app/jwt_secret":  {"value": "dev-jwt-secret-abc123", "created": "2024-02-01", "rotated": None},
}


class SecretsManagerClient:
    """
    Wraps AWS Secrets Manager operations with:
    - Consistent error handling
    - Audit logging
    - Mock mode for local development
    - Rotation tracking and staleness detection
    """

    ROTATION_THRESHOLD_DAYS = 90

    def __init__(self, use_mock=True, region="us-east-1"):
        self.use_mock   = use_mock
        self.region     = region
        self._store     = dict(_MOCK_STORE)
        self._audit_log = []

        if not use_mock:
            try:
                import boto3
                self._client = boto3.client("secretsmanager", region_name=region)
                print(f"[+] Connected to AWS Secrets Manager in {region}")
            except ImportError:
                print("[!] boto3 not installed. Falling back to mock mode.")
                self.use_mock = True
            except Exception as e:
                print(f"[!] AWS connection failed: {e}. Falling back to mock mode.")
                self.use_mock = True

    def _log(self, action, secret_name, success=True, note=""):
        entry = {
            "timestamp":   datetime.datetime.now().isoformat(),
            "action":      action,
            "secret_name": secret_name,
            "success":     success,
            "note":        note,
        }
        self._audit_log.append(entry)

    def get_secret(self, secret_name):
        try:
            if self.use_mock:
                secret = self._store.get(secret_name)
                if not secret:
                    raise KeyError(f"Secret '{secret_name}' not found.")
                value = secret["value"]
            else:
                response = self._client.get_secret_value(SecretId=secret_name)
                value    = response.get("SecretString", response.get("SecretBinary"))

            self._log("GET", secret_name, success=True)
            print(f"[+] Retrieved secret: {secret_name}")
            return value

        except Exception as e:
            self._log("GET", secret_name, success=False, note=str(e))
            print(f"[!] Failed to retrieve '{secret_name}': {e}")
            return None

    def create_secret(self, secret_name, secret_value, description=""):
        try:
            if self.use_mock:
                if secret_name in self._store:
                    raise ValueError(f"Secret '{secret_name}' already exists. Use update_secret() instead.")
                self._store[secret_name] = {
                    "value":   secret_value,
                    "created": datetime.datetime.now().strftime("%Y-%m-%d"),
                    "rotated": None,
                }
            else:
                self._client.create_secret(
                    Name=secret_name,
                    SecretString=secret_value,
                    Description=description,
                )

            self._log("CREATE", secret_name, success=True)
            print(f"[+] Created secret: {secret_name}")
            return True

        except Exception as e:
            self._log("CREATE", secret_name, success=False, note=str(e))
            print(f"[!] Failed to create '{secret_name}': {e}")
            return False

    def update_secret(self, secret_name, new_value):
        try:
            if self.use_mock:
                if secret_name not in self._store:
                    raise KeyError(f"Secret '{secret_name}' not found. Use create_secret() first.")
                self._store[secret_name]["value"]   = new_value
                self._store[secret_name]["rotated"] = datetime.datetime.now().strftime("%Y-%m-%d")
            else:
                self._client.update_secret(SecretId=secret_name, SecretString=new_value)

            self._log("UPDATE", secret_name, success=True)
            print(f"[+] Updated secret: {secret_name}")
            return True

        except Exception as e:
            self._log("UPDATE", secret_name, success=False, note=str(e))
            print(f"[!] Failed to update '{secret_name}': {e}")
            return False

    def delete_secret(self, secret_name, recovery_window_days=30):
        try:
            if self.use_mock:
                if secret_name not in self._store:
                    raise KeyError(f"Secret '{secret_name}' not found.")
                del self._store[secret_name]
            else:
                self._client.delete_secret(
                    SecretId=secret_name,
                    RecoveryWindowInDays=recovery_window_days,
                )

            self._log("DELETE", secret_name, success=True,
                      note=f"Recovery window: {recovery_window_days} days")
            print(f"[+] Scheduled deletion for: {secret_name}")
            return True

        except Exception as e:
            self._log("DELETE", secret_name, success=False, note=str(e))
            print(f"[!] Failed to delete '{secret_name}': {e}")
            return False

    def list_secrets(self):
        if self.use_mock:
            names = list(self._store.keys())
        else:
            response = self._client.list_secrets()
            names    = [s["Name"] for s in response.get("SecretList", [])]

        self._log("LIST", "*", success=True, note=f"{len(names)} secrets found")
        return names

    def audit_rotation(self):
        print(f"\n[+] Running rotation audit (threshold: {self.ROTATION_THRESHOLD_DAYS} days)...\n")
        today    = datetime.date.today()
        findings = []

        store = self._store if self.use_mock else {}

        for name, data in store.items():
            rotated_str = data.get("rotated")

            if rotated_str is None:
                days_since = None
                status     = "NEVER ROTATED"
                severity   = "HIGH"
            else:
                rotated_date = datetime.date.fromisoformat(rotated_str)
                days_since   = (today - rotated_date).days
                if days_since > self.ROTATION_THRESHOLD_DAYS:
                    status   = f"STALE ({days_since} days)"
                    severity = "MEDIUM"
                else:
                    status   = f"OK ({days_since} days)"
                    severity = "INFO"

            findings.append({
                "secret":              name,
                "status":              status,
                "severity":            severity,
                "days_since_rotation": days_since,
            })
            print(f"  [{severity:<6}] {name}")
            print(f"           Rotation: {status}\n")

        return findings

    def print_audit_log(self):
        print("\n" + "="*65)
        print("  AUDIT LOG")
        print("="*65)
        for entry in self._audit_log:
            status = "✓" if entry["success"] else "✗"
            print(f"  {status} [{entry['timestamp'][:19]}] {entry['action']:8} {entry['secret_name']}")
            if entry["note"]:
                print(f"      Note: {entry['note']}")
        print("="*65 + "\n")

    def export_audit_log(self, output_dir="sample_output"):
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = os.path.join(output_dir, f"secrets_audit_{timestamp}.json")
        with open(filename, "w") as f:
            json.dump(self._audit_log, f, indent=4)
        print(f"[+] Audit log saved: {filename}")
        return filename


if __name__ == "__main__":
    print("\n[DEMO MODE — Running all operations]\n")
    client = SecretsManagerClient(use_mock=True)
    client.list_secrets()
    client.get_secret("prod/db/password")
    client.create_secret("staging/app/api_key", "new-staging-key-xyz")
    client.update_secret("dev/app/jwt_secret", "rotated-jwt-secret-2024")
    client.delete_secret("staging/app/api_key")
    client.audit_rotation()
    client.print_audit_log()
    client.export_audit_log()
