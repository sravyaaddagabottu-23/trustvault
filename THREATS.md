# THREATS.md

How I think TrustVault could be broken, what I did about each, and what I knowingly left open.

## Closed (fixed and tested)

| # | Threat | What I did | Test |
|---|---|---|---|
| 1 | A user guesses a document ID and downloads someone else's file | One function, can_access, is called by every document route. Only the owner or a user with an active grant passes. | test_stranger_cannot_download |
| 2 | Admin reads document content | Admin has no special rule in can_access. Admin sees activity only. | test_admin_cannot_read_content |
| 3 | A revoked user keeps access | Grants have revoked_at and are checked in the database on every request. The token holds only the user id, never permissions. | test_grant_then_revoke_is_immediate |
| 4 | A read-only grant is used to edit or delete | Edit needs an edit grant. Delete, grant and revoke are owner only. | test_read_grant_cannot_edit_or_delete |
| 5 | List or search leaks other users' documents | The same rule is applied as an SQL filter. Search filters only narrow results. | test_listing_hides_other_users_documents |
| 6 | Learning which document IDs exist | Refusals return 404, not 403, so a missing document and a forbidden one look the same. | same tests |
| 7 | Refused attempts leave no record | Every decision, allowed or refused, is written to the audit log with allowed true or false. | test_denied_attempts_are_audited |
| 8 | Bad uploads (.exe, empty, oversized) | Extension allow-list, 5 MB limit, empty files rejected. | test_bad_uploads_rejected |
| 9 | Path traversal through the uploaded filename | Files are saved under a server-generated uuid. The user's filename is never used as a path. | NOT tested yet. Reasoned from the code only. |
| 10 | Default passwords or secret key on the live system | The server refuses to start without the secret and seed passwords unless TRUSTVAULT_ENV=dev. | I removed the variable and ran python -c "import app.auth". It stopped with: RuntimeError: TRUSTVAULT_SECRET is not set. Refusing to start. |
| 11 | Disabled user keeps using an old token | The user is re-read from the database on every request and rejected if is_active is false. | Not covered by an automated test. |
| 12 | Admin self-registers | Registration only accepts owner or viewer. Admin accounts come from the seed script. | Not covered by an automated test. |

## Knowingly accepted (weak, and why)

- **Audit chain can be rewritten.** The hash chain detects edits to a row, but someone with direct database access could recompute the whole chain. A fix would be storing the latest hash outside the database. I left it because of time.
- **No token revocation.** A JWT is valid for 60 minutes. Disabling a user works at once, but a stolen token for an active user works until it expires.
- **No rate limiting or lockout.** Password guessing against /auth/login is possible.
- **Open registration.** Anyone can create an owner or viewer account.
- **Audit IP is the proxy's IP on Render**, because I use request.client.host.
- **Free hosting is not durable.** SQLite and uploaded files are wiped when Render restarts. A real deployment needs PostgreSQL and object storage.
- **The rule exists in two places** (can_access and the list SQL filter). A change must be made in both.
- **File type is trusted from the extension**, not the file contents, and there is no virus scan.
- **Demo seed accounts exist on the live system.** Their passwords are set through environment variables, not in the code.

## Test honesty

I commented out the authorize() call in the download route and ran the tests. 4 tests failed: test_stranger_cannot_download, test_admin_cannot_read_content, test_grant_then_revoke_is_immediate, test_denied_attempts_are_audited. I restored the line and all 7 passed again.

## Attacks I tried myself on the live site

- Download without logging in: 401 "Not authenticated"
- /documents/999/download as owner: 404 "Not found"
- A second owner account downloading the first owner's file: 404 "Not found"
