# AWS Secrets Manager Wrapper

A Python module that wraps **AWS Secrets Manager** operations with consistent error handling, full audit logging, and a CLI interface. Includes mock mode for local development — no AWS account required to run or test.

---

## What It Does

| Operation | Method | Maps To |
|---|---|---|
| Retrieve secret | `get_secret(name)` | `boto3 get_secret_value` |
| Create secret | `create_secret(name, value)` | `boto3 create_secret` |
| Update/rotate | `update_secret(name, value)` | `boto3 update_secret` |
| Delete | `delete_secret(name)` | `boto3 delete_secret` |
| List all names | `list_secrets()` | `boto3 list_secrets` |
| Rotation audit | `audit_rotation()` | Custom — maps to NIST IA-5 |
| Export audit log | `export_audit_log()` | JSON compliance evidence |

---

## Quick Start
```bash
git clone https://github.com/YOUR_USERNAME/aws-secrets-wrapper.git
cd aws-secrets-wrapper

# Run demo (mock mode — no AWS needed)
python src/secrets_manager.py

# CLI usage
python src/secrets_manager.py list
python src/secrets_manager.py get prod/db/password
python src/secrets_manager.py create myapp/api_key "supersecret"
python src/secrets_manager.py audit
```

---

## Connect to Real AWS
```bash
pip install boto3
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

Then in code:
```python
client = SecretsManagerClient(use_mock=False, region="us-east-1")
```

---

## Security Design Decisions

- **Never log secret values** — only names and operation results are recorded
- **Environment variables** for credentials — never hardcoded
- **Recovery window** on deletions — AWS requires 7–30 day window before permanent removal
- **Rotation audit** flags secrets not rotated in 90 days — maps to NIST IA-5

---

## Running Tests
```bash
pip install pytest
python -m pytest tests/ -v
```

10 unit tests covering all CRUD operations, error handling, and audit log behavior.

---

## Project Structure
```
aws-secrets-wrapper/
├── src/
│   └── secrets_manager.py   # Core logic and CLI
├── tests/
│   └── test_secrets_manager.py
├── sample_output/           # Audit logs saved here (git-ignored)
├── .github/
│   └── workflows/
│       └── ci.yml
├── .gitignore
└── README.md
```

---

## Roadmap

- [ ] Connect to real AWS Secrets Manager via boto3
- [ ] Add HashiCorp Vault support
- [ ] Auto-rotate secrets on schedule via AWS Lambda
- [ ] Slack alert when secret rotation is overdue

---

## Author

**Kareem Martinez** | Cybersecurity Professional | DOE Q Clearance
Pursuing: CCSP · CISSP · AWS Certified Cloud Practitioner
