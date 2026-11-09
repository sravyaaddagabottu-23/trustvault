# TrustVault

Secure document sharing with an audit trail. Python, FastAPI, SQLAlchemy, SQLite.

**Live:** https://trustvault-0zsp.onrender.com/docs
(Free Render hosting sleeps after inactivity. The first request can take ~50 seconds. Open it once and wait.)

## Demo accounts (live system)

| Role | Email | Password |
|---|---|---|
| Admin | admin@trustvault.test | 08c66b60f13f208a68be177a437f986d|
| Owner | owner@trustvault.test | bf23762a6c44be453744473ea792998c|
| Viewer | viewer@trustvault.test | ac7b9106011309554188b9b09e162852|

In /docs click **Authorize** and enter the email as username.
Note: free hosting wipes data on restart. Accounts are recreated on startup; uploaded files are not kept.

## Permission model (in my own words)

A document is reachable only by **its owner** or by a user holding an **active grant** (read or edit) on it. Nobody else, including the admin.

- **Admin**: manages users, reads the audit log, verifies the audit chain. Cannot read document content.
- **Owner**: uploads documents, reads, edits and deletes their own, grants and revokes access to named users.
- **Viewer**: sees only documents granted to them (read, or edit if edit was granted).

Every document route calls one function, `can_access` (app/permissions.py), through `authorize()`. The user is re-read from the database on every request and the token holds only the user id, so revoking a grant or disabling a user takes effect on the next request. Refusals return 404, not 403, so IDs cannot be probed. Every decision, allowed or refused, is written to a hash-chained audit log.

## API: who may call what

| Endpoint | Who |
|---|---|
| POST /auth/register | Anyone (owner or viewer only) |
| POST /auth/login | Anyone |
| GET /me | Any logged-in user |
| POST /documents (upload) | Owner role |
| GET /documents (list/search: q, category, owner, date_from, date_to) | Logged-in; returns only own or granted documents |
| GET /documents/{id}/download | Document owner, or active read/edit grant |
| PUT /documents/{id}/content | Document owner, or active edit grant |
| DELETE /documents/{id} | Document owner only |
| POST /documents/{id}/grants | Document owner only |
| GET /documents/{id}/grants | Document owner only |
| DELETE /documents/{id}/grants/{user_id} | Document owner only |
| GET /admin/audit | Admin |
| GET /admin/audit/verify | Admin |
| GET /admin/users | Admin |
| POST /admin/users/{id}/disable | Admin |

## Run locally (Windows PowerShell)

```
git clone https://github.com/sravyaaddagabottu-23/trustvault.git
cd trustvault
python -m venv venv
venv\Scripts\activate     (Max/Linux: source  venv/bin/activate and export TRUSTVAULT_ENV=dev.)
pip install -r requirements.txt
pytest -q
$env:TRUSTVAULT_ENV = "dev"
python seed.py
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000/docs. Dev mode uses insecure default passwords (see seed.py). Never set TRUSTVAULT_ENV on a real deployment.

## Deploy (Render)

Build: `pip install -r requirements.txt`
Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
Required environment variables (the server refuses to start without them):
`PYTHON_VERSION=3.12.0`, `TRUSTVAULT_SECRET`, `SEED_ADMIN_PW`, `SEED_OWNER_PW`, `SEED_VIEWER_PW`.

## Database

SQLAlchemy models in app/models.py (users, documents, grants, audit_log). Tables are created on startup (`init_db`); `python seed.py` creates the demo users locally.

## Tests

```
pytest -q
```
7 tests: a stranger and the admin cannot download, grant then revoke is immediate, a read grant cannot edit or delete, listing hides other users' documents, refused attempts are audited, bad uploads are rejected. See THREATS.md for what I tested, including removing the authorize() line to confirm the tests fail.

## What I deliberately did not build

Groups, folder inheritance, sharing links for people outside the system, versions, recovery of deleted files (deletes are soft), a web UI (the API is explored through /docs), rate limiting, token revocation. Reasons and other known weaknesses are in THREATS.md.

## Unfinished / known limits

- SQLite and local files: not durable on free hosting.
- Open self-registration.
- Audit chain detects tampering but cannot prevent a full rewrite by someone with database access.
- No web UI; the API is used through the/docs page.

## Files

THREATS.md (threat list), PROMPTS.md (how I used AI, including where it was wrong).
