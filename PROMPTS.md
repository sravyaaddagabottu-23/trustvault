# PROMPTS.md



## Entry 1- 2026-11-01

**Asked:** Explain TrustVault problem statement and give a 7-day plan.

**Produced:** Summary of requirements and a day-wise plan.

**Wrong/issue:**(to fill as I work)

**What I did:**Chose Python + FastAPI. Commit:(https://github.com/sravyaaddagabottu-23/trustvault/commit/a6beda074b7b3e53d88be0f7b269475bf8f30405)



## Entry 2- 2026-11-01

**Asked** how to set up the database models and keep the database file out of GitHub.

**Wrong/issue** The AI gave me models.py and told me to add trustvault.db and uploads/to .gitignore.

git add and git commit first.Because of that,trustvault.db was already tracked and got pushed to GitHub.Adding a file to .gitignore does not remove a file that git is already tracking.

**what I did** Inoticed trustvault.db on the GitHub page,removed it from tracking with git rm --cached trustvault.db, added trustvault.db and uploads/ to .gitignore by editing the file manually, and pushed.the DB was empty at the time,so no credentials were exposed.Commit(https://github.com/sravyaaddagabottu-23/trustvault/commit/4322cedd81fdbcf3496ee085c3c816d5a7c2c30f)


## Entry 3 2026-11-03

**Asked:** Write auth.py(login,bcrypt password hashing,JWT) and permissions.py(one can_access function that every document route must call).

**Produced:** auth.py and permissions.py. the token holds only the user id,and role and is_active are re-read from the DB on every request.can_access allows the owner,or a user with an active(not revoked)grant. Admin gets no document access. refused attempts are logged and return 404.

**Wrong/issue:** In auth.py, the AI used request.client.host directly inside log_event.in permissions.py it guarded the same value with "if request.client else None".because of this inconsistency, auth.py can crash when request.client is None,and the failed login token would not be logged,also,bwhind a proxy like Render,this IP will be the proxy's IP,not the real user's,so the IP in the audit log is not fully trustworthy.

**What I did:** I added a client_ip(request) helper in auth.py that returns None when request.client is missing, and used it in get_current_user and require_role. i will note the proxy-IP limitations in THREATS.md. Commit:(https://github.com/sravyaaddagabottu-23/trustvault/commit/a0e8cdbe37b16be78e4a84c9db60d12ad3c4947b)

## Entry 4 - 2026-11-05

**Asked:** How to deploy to Render and create demo users with passwords taken from environment variables.

**Produced:** A seed_demo_users function that reads SEED_ADMIN_PW, SEED_OWNER_PW and SEED_VIEWER_PW, with a hardcoded default password if the variable is missing.

**Wrong / issue:** I typed the variable name as SEED_ADMIN-PW (hyphen) instead of SEED_ADMIN_PW. The deploy still succeeded because the code silently fell back to the default admin password, which is visible in the public code. I noticed only because logging in with my new admin password returned 401. The fallback hid a misconfiguration and would have left a guessable admin password on a live system.

**What I did:** Fixed the variable name in Render and redeployed. Confirmed the old default password now returns 401. Then changed the code so the server refuses to start without the secret and seed passwords unless TRUSTVAULT_ENV=dev, and confirmed the RuntimeError locally. Commit: PASTE-COMMIT-LINK

## Entry 5 - 2026-11-06

**Asked:** Write tests that prove one user cannot reach another user's documents.

**Produced:** Seven pytest tests in tests/test_access.py.

**Wrong / issue:** Nothing was wrong that I found in the first run; all 7 passed. But passing tests prove nothing if they would also pass without the check. So I tested the tests: I commented out the authorize() line in the download route.

**What I did:** 4 tests failed (test_stranger_cannot_download, test_admin_cannot_read_content, test_grant_then_revoke_is_immediate, test_denied_attempts_are_audited), so the tests do depend on that line. I restored it and all 7 passed. Commit: PASTE-COMMIT-LINK
