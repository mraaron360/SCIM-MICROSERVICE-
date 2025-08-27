# Project: scim-bridge

A minimal, production‑style **SCIM 2.0** microservice for IAM engineers. Implements `/scim/v2/Users` (full CRUD + PATCH) and essentials for `/ServiceProviderConfig`, `/Schemas`, and `/ResourceTypes`. Uses **Flask + SQLAlchemy (SQLite)**, Bearer‑token auth, and ships with Docker, seed data, and pytest.

> Copy this whole repo to GitHub as `scim-bridge` (or any name). The README below is the top‑level `README.md`.

---

## 📁 Directory Tree

```
scim-bridge/
├─ app.py
├─ scim.py
├─ models.py
├─ storage.py
├─ requirements.txt
├─ .env.example
├─ README.md
├─ Dockerfile
├─ docker-compose.yml
├─ scripts/
│  └─ seed.py
└─ tests/
   └─ test_users.py
```

---

## README.md

# 🔐 SCIM 2.0 Microservice — "scim-bridge"

A lightweight **SCIM 2.0** server that you can wire up to Okta or Microsoft Entra ID (Azure AD) as a **SCIM Provisioning** target. Perfect for demos, interviews, and learning real IAM engineering.

### Features
- **Users API**: `GET/POST/PUT/PATCH/DELETE /scim/v2/Users` with pagination, filtering (`eq`), and soft‑deactivate on delete.
- **SCIM Essentials**: `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`, `/scim/v2/ResourceTypes`.
- **Auth**: Simple **Bearer token** (set `API_TOKEN` in `.env`).
- **Storage**: SQLite via SQLAlchemy; easy to swap for Postgres.
- **Dev UX**: Dockerfile, `docker-compose.yml`, seed script, pytest.

---

## ⚡ Quick Start

### 1) Local (Python 3.11+)
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# edit .env to set API_TOKEN (any string you like)
python scripts/seed.py
python app.py  # runs on http://127.0.0.1:8000
```

### 2) Docker
```bash
docker build -t scim-bridge:latest .
docker run -p 8000:8000 --env-file .env scim-bridge:latest
```
_or_
```bash
docker-compose up --build
```

### 3) Smoke Test
```bash
TOKEN="changeme"  # must match API_TOKEN in .env
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/healthz
curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:8000/scim/v2/Users?startIndex=1&count=10"
```

---

## 🔌 Hooking up to Okta (SCIM Provisioning)
1. In Okta Admin, **Applications → Browse App Catalog → SCIM 2.0 Test App (Header Auth)** (or create an App Integration with SCIM).
2. **Base URL**: `http://YOUR_HOST:8000/scim/v2`
3. **Unique identifier field for users**: `userName` (default).
4. **Supported provisioning actions**: Create, Update, Deactivate.
5. **Authentication Mode**: **HTTP Header**. Header name: `Authorization`. Value: `Bearer YOUR_API_TOKEN`.
6. Test **GET Users** in Okta → it should return users from the seed data.

## 🔌 Hooking up to Microsoft Entra ID (Azure AD)
1. In Entra ID, **Enterprise Applications → New application → Create your own application** → **Provisioning**.
2. **Provisioning Mode**: SCIM.
3. **Tenant URL**: `http://YOUR_HOST:8000/scim/v2`
4. **Secret Token**: your `API_TOKEN`.
5. **Test Connection** and **Save**.

> 
> **Note**: This service implements a practical subset of SCIM 2.0 for demos. You can extend schemas and group handling as needed.

---

## 🧪 Useful Requests

### Create User
```bash
curl -s -X POST http://localhost:8000/scim/v2/Users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
    "externalId":"ext-1001",
    "userName":"jdoe",
    "name":{"givenName":"John","familyName":"Doe"},
    "displayName":"John Doe",
    "active":true,
    "emails":[{"value":"jdoe@example.com","type":"work","primary":true}]
  }'
```

### Filter Users (eq)
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/scim/v2/Users?filter=userName%20eq%20%22jdoe%22"
```

### Patch (deactivate)
```bash
curl -s -X PATCH http://localhost:8000/scim/v2/Users/<id> \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations":[{"op":"replace","path":"active","value":false}]
  }'
```

---

## 📚 What you’ll learn / showcase
- SCIM resource modeling and JSON mapping
- REST API design, authn (Bearer), and idempotent operations
- Filter + pagination implementation (startIndex/count)
- Cloud IdP integration (Okta/Entra) provisioning flows

---

## 🧱 Tech
- Python 3.11, Flask, SQLAlchemy (SQLite)
- Docker, docker‑compose, pytest

---

## 📜 License
MIT

---

## app.py
```python
import os
from datetime import datetime, timezone
from uuid import uuid4
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from sqlalchemy import select
from sqlalchemy.exc import NoResultFound

from storage import SessionLocal, init_db
from models import User
from scim import (
    scim_error, to_scim_user, list_response, parse_filter_eq,
    require_bearer, now_rfc3339, base_location,
    SERVICE_PROVIDER_CONFIG, SCHEMAS_DOC, RESOURCE_TYPES_DOC,
)

load_dotenv()

app = Flask(__name__)
init_db()

API_TOKEN = os.getenv("API_TOKEN", "changeme")
BASE_PATH = "/scim/v2"

@app.before_request
def auth_guard():
    if request.path.startswith(BASE_PATH) or request.path == "/healthz":
        ok = require_bearer(request.headers.get("Authorization"), API_TOKEN)
        if not ok:
            return jsonify(scim_error(401, detail="Missing or invalid bearer token")), 401

@app.get("/healthz")
def healthz():
    return {"status": "ok", "time": now_rfc3339()}

# ---- SCIM metadata ----
@app.get(f"{BASE_PATH}/ServiceProviderConfig")
def service_provider_config():
    return SERVICE_PROVIDER_CONFIG

@app.get(f"{BASE_PATH}/Schemas")
def schemas():
    return SCHEMAS_DOC

@app.get(f"{BASE_PATH}/ResourceTypes")
def resource_types():
    return RESOURCE_TYPES_DOC

# ---- Users collection ----
@app.get(f"{BASE_PATH}/Users")
def list_users():
    session = SessionLocal()
    try:
        q = session.query(User)
        # Filtering: support eq on id, userName, externalId
        filt = request.args.get("filter")
        if filt:
            key, value = parse_filter_eq(filt)
            if key == "id":
                q = q.filter(User.id == value)
            elif key.lower() == "username":
                q = q.filter(User.userName == value)
            elif key == "externalId":
                q = q.filter(User.externalId == value)
            else:
                return jsonify(scim_error(400, detail=f"Unsupported filter attribute: {key}")), 400

        # Pagination
        start_index = int(request.args.get("startIndex", 1))
        count = int(request.args.get("count", 100))
        total = q.count()
        items = q.offset(max(0, start_index - 1)).limit(count).all()
        resources = [to_scim_user(u, base_location(request)) for u in items]
        return list_response(resources, start_index, count, total)
    finally:
        session.close()

@app.post(f"{BASE_PATH}/Users")
def create_user():
    session = SessionLocal()
    try:
        data = request.get_json(force=True)
        if not isinstance(data, dict):
            return jsonify(scim_error(400, detail="Invalid JSON")), 400

        # minimal schema handling
        user = User(
            id=str(uuid4()),
            externalId=data.get("externalId"),
            userName=data.get("userName"),
            givenName=(data.get("name") or {}).get("givenName"),
            familyName=(data.get("name") or {}).get("familyName"),
            displayName=data.get("displayName"),
            email=(data.get("emails") or [{}])[0].get("value"),
            active=bool(data.get("active", True)),
            created=datetime.now(timezone.utc),
            lastModified=datetime.now(timezone.utc),
        )
        session.add(user)
        session.commit()
        resp = to_scim_user(user, base_location(request))
        return jsonify(resp), 201
    finally:
        session.close()

@app.get(f"{BASE_PATH}/Users/<user_id>")
def get_user(user_id):
    session = SessionLocal()
    try:
        user = session.get(User, user_id)
        if not user:
            return jsonify(scim_error(404, detail="User not found")), 404
        return to_scim_user(user, base_location(request))
    finally:
        session.close()

@app.put(f"{BASE_PATH}/Users/<user_id>")
def replace_user(user_id):
    session = SessionLocal()
    try:
        user = session.get(User, user_id)
        if not user:
            return jsonify(scim_error(404, detail="User not found")), 404
        data = request.get_json(force=True)
        user.externalId = data.get("externalId")
        user.userName = data.get("userName")
        user.givenName = (data.get("name") or {}).get("givenName")
        user.familyName = (data.get("name") or {}).get("familyName")
        user.displayName = data.get("displayName")
        user.email = (data.get("emails") or [{}])[0].get("value")
        user.active = bool(data.get("active", True))
        user.lastModified = datetime.now(timezone.utc)
        session.commit()
        return to_scim_user(user, base_location(request))
    finally:
        session.close()

@app.patch(f"{BASE_PATH}/Users/<user_id>")
def patch_user(user_id):
    session = SessionLocal()
    try:
        user = session.get(User, user_id)
        if not user:
            return jsonify(scim_error(404, detail="User not found")), 404
        payload = request.get_json(force=True)
        ops = payload.get("Operations", [])
        for op in ops:
            operation = (op.get("op") or "").lower()
            path = op.get("path")
            value = op.get("value")
            if operation in ("replace", "add"):
                if path == "active":
                    user.active = bool(value)
                elif path == "name.givenName":
                    user.givenName = value
                elif path == "name.familyName":
                    user.familyName = value
                elif path == "displayName":
                    user.displayName = value
                elif path == "emails" and isinstance(value, list) and value:
                    user.email = value[0].get("value")
                else:
                    # Basic pathless replace handling (object merge)
                    if isinstance(value, dict):
                        if "active" in value:
                            user.active = bool(value["active"])
                        name = value.get("name") or {}
                        if "givenName" in name:
                            user.givenName = name.get("givenName")
                        if "familyName" in name:
                            user.familyName = name.get("familyName")
                        if "displayName" in value:
                            user.displayName = value.get("displayName")
                        emails = value.get("emails")
                        if isinstance(emails, list) and emails:
                            user.email = emails[0].get("value")
            elif operation == "remove":
                if path == "emails":
                    user.email = None
                elif path == "displayName":
                    user.displayName = None
                # add more removes as needed
            else:
                return jsonify(scim_error(400, detail=f"Unsupported op: {operation}")), 400
        user.lastModified = datetime.now(timezone.utc)
        session.commit()
        return to_scim_user(user, base_location(request))
    finally:
        session.close()

@app.delete(f"{BASE_PATH}/Users/<user_id>")
def delete_user(user_id):
    session = SessionLocal()
    try:
        user = session.get(User, user_id)
        if not user:
            return "", 204  # idempotent
        # SCIM delete often means deactivate
        user.active = False
        user.lastModified = datetime.now(timezone.utc)
        session.commit()
        return "", 204
    finally:
        session.close()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
```

---

## scim.py
```python
import re
from datetime import datetime, timezone
from flask import request

SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
USER_CORE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_CORE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

SERVICE_PROVIDER_CONFIG = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    "patch": {"supported": True},
    "bulk": {"supported": False},
    "filter": {"supported": True, "maxResults": 200},
    "sort": {"supported": False},
    "changePassword": {"supported": False},
    "etag": {"supported": False},
    "authenticationSchemes": [
        {
            "name": "OAuth Bearer Token",
            "description": "Send 'Authorization: Bearer <token>'",
            "type": "oauthbearertoken",
            "primary": True
        }
    ]
}

SCHEMAS_DOC = {
    "Resources": [
        {
            "id": USER_CORE_SCHEMA,
            "name": "User",
            "attributes": [
                {"name": "userName", "type": "string", "required": True},
                {"name": "name", "type": "complex", "subAttributes": [
                    {"name": "givenName", "type": "string"},
                    {"name": "familyName", "type": "string"}
                ]},
                {"name": "displayName", "type": "string"},
                {"name": "active", "type": "boolean"},
                {"name": "emails", "type": "complex", "multiValued": True, "subAttributes": [
                    {"name": "value", "type": "string"},
                    {"name": "type", "type": "string"},
                    {"name": "primary", "type": "boolean"}
                ]}
            ]
        },
        {
            "id": GROUP_CORE_SCHEMA,
            "name": "Group",
            "attributes": [
                {"name": "displayName", "type": "string", "required": True},
                {"name": "members", "type": "complex", "multiValued": True}
            ]
        }
    ]
}

RESOURCE_TYPES_DOC = {
    "Resources": [
        {
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": USER_CORE_SCHEMA,
        },
        {
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "schema": GROUP_CORE_SCHEMA,
        }
    ]
}


def now_rfc3339(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def base_location(req) -> str:
    # e.g., http://localhost:8000/scim/v2
    url_root = req.url_root.rstrip("/")
    return f"{url_root}/scim/v2"


def scim_error(status: int, detail: str = "", scimType: str | None = None):
    err = {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(status),
        "detail": detail or "",
    }
    if scimType:
        err["scimType"] = scimType
    return err


def list_response(resources, start_index: int, count: int, total: int):
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


def to_scim_user(u, base_url: str):
    return {
        "schemas": [USER_CORE_SCHEMA],
        "id": u.id,
        "externalId": u.externalId,
        "userName": u.userName,
        "name": {
            "givenName": u.givenName,
            "familyName": u.familyName,
        },
        "displayName": u.displayName,
        "active": bool(u.active),
        "emails": ([{"value": u.email, "type": "work", "primary": True}] if u.email else []),
        "meta": {
            "resourceType": "User",
            "created": now_rfc3339(u.created),
            "lastModified": now_rfc3339(u.lastModified),
            "location": f"{base_url}/Users/{u.id}",
        },
    }


_FILTER_RE = re.compile(r"^(id|userName|externalId)\s+eq\s+\"([^\"]+)\"$", re.IGNORECASE)


def parse_filter_eq(expr: str):
    """Parse expressions like: userName eq "jdoe""" 
    m = _FILTER_RE.match((expr or "").strip())
    if not m:
        raise ValueError("Only simple 'attribute eq \"value\"' filters are supported")
    key = m.group(1)
    value = m.group(2)
    return key, value


def require_bearer(header_value: str | None, token_expected: str) -> bool:
    if not header_value:
        return False
    parts = header_value.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    return parts[1] == token_expected
```

---

## models.py
```python
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Boolean, DateTime

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    externalId: Mapped[str | None] = mapped_column(String(128))
    userName: Mapped[str | None] = mapped_column(String(128), index=True, unique=True)
    givenName: Mapped[str | None] = mapped_column(String(128))
    familyName: Mapped[str | None] = mapped_column(String(128))
    displayName: Mapped[str | None] = mapped_column(String(256))
    email: Mapped[str | None] = mapped_column(String(256), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created: Mapped[DateTime] = mapped_column(DateTime(timezone=True))
    lastModified: Mapped[DateTime] = mapped_column(DateTime(timezone=True))
```

---

## storage.py
```python
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base

DB_URL = os.getenv("DATABASE_URL", "sqlite:///scim.db")
engine = create_engine(DB_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def init_db():
    Base.metadata.create_all(bind=engine)
```

---

## scripts/seed.py
```python
import os
from datetime import datetime, timezone
from uuid import uuid4
from dotenv import load_dotenv

from storage import SessionLocal, init_db
from models import User

load_dotenv()

if __name__ == "__main__":
    init_db()
    session = SessionLocal()
    try:
        users = [
            User(
                id=str(uuid4()),
                externalId="ext-0001",
                userName="alice",
                givenName="Alice",
                familyName="Stone",
                displayName="Alice Stone",
                email="alice@example.com",
                active=True,
                created=datetime.now(timezone.utc),
                lastModified=datetime.now(timezone.utc),
            ),
            User(
                id=str(uuid4()),
                externalId="ext-0002",
                userName="bob",
                givenName="Bob",
                familyName="Nguyen",
                displayName="Bob Nguyen",
                email="bob@example.com",
                active=True,
                created=datetime.now(timezone.utc),
                lastModified=datetime.now(timezone.utc),
            ),
        ]
        for u in users:
            session.merge(u)
        session.commit()
        print("Seeded users: alice, bob")
    finally:
        session.close()
```

---

## tests/test_users.py
```python
import os
import json
from app import app

TOKEN = os.getenv("API_TOKEN", "changeme")


def auth_headers():
    return {"Authorization": f"Bearer {TOKEN}"}


def test_healthz():
    client = app.test_client()
    rv = client.get("/healthz", headers=auth_headers())
    assert rv.status_code == 200


def test_list_users():
    client = app.test_client()
    rv = client.get("/scim/v2/Users", headers=auth_headers())
    assert rv.status_code == 200
    data = rv.get_json()
    assert "Resources" in data
```

---

## requirements.txt
```
Flask==3.0.2
SQLAlchemy==2.0.32
python-dotenv==1.0.1
```

---

## .env.example
```
# Copy to .env and set your values
API_TOKEN=changeme
PORT=8000
# DATABASE_URL=sqlite:///scim.db
```

---

## Dockerfile
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PORT=8000
EXPOSE 8000
CMD ["python", "app.py"]
```

---

## docker-compose.yml
```yaml
version: "3.9"
services:
  scim:
    build: .
    ports:
      - "8000:8000"
    env_file: .env
    restart: unless-stopped
    volumes:
      - ./:/app
