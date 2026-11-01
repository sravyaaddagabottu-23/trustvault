\#PROMPTS.md



\##Entry 1- 2026-11-01

\*\*Asked:\*\*Explain TrustVault problem statement and give a 7-day plan.

\*\*Produced:\*\*Summary of requirements and a day-wise plan.

\*\*Wrong/issue:\*\*(to fill as I work)

\*\*What I did:\*\*Chose Python + FastAPI. Commit:(link later)


##Entry 2- 2026-11-01
**Asked** how to set up the database models and keep the database file out of GitHub.
**Wrong/issue** The AI gave me models.py and told me to add trustvault.db and uploads/to .gitignore.
git add and git commit first.Because of that,trustvault.db was already tracked and got pushed to GitHub.Adding a file to .gitignore does not remove a file that git is already tracking.
**what I did** Inoticed trustvault.db on the GitHub page,removed it from tracking with git rm --cached trustvault.db, added trustvault.db and uploads/ to .gitignore by editing the file manually, and pushed.the DB was empty at the time,so no credentials were exposed. Commit(https://github.com/sravyaaddagabottu-23/trustvault/commit/4322cedd81fdbcf3496ee085c3c816d5a7c2c30f)
