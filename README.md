# Daybook

A personal prayer and Quran tilawat tracker. The UI is static HTML/CSS/JavaScript, the authenticated API runs as Vercel Python Functions, and MongoDB Atlas stores accounts, sessions, prayer records and Quran sessions.

## Online deployment (Vercel + MongoDB Atlas)

1. Push this project to a GitHub repository.
2. In MongoDB Atlas, create a free cluster, create a database user with read/write access to the `daybook` database, and configure the Atlas IP access list for your Vercel app. Vercel has dynamic outbound IPs by default; fixed egress IPs are a paid Vercel feature. If you use `0.0.0.0/0` as a Hobby-plan workaround, it allows connections from anywhere, so use a generated strong password and a database user limited to read/write access on `daybook`. Atlas warns that `/0` can expose the deployment to unauthorized access.
3. Copy the Atlas application connection string. Replace its password placeholder with the database user's password.
4. In Vercel, import the GitHub repository as a project. `vercel.json` selects the **Other** framework preset so Vercel deploys the `api/*.py` files as separate functions and serves the frontend files statically. Vercel installs PyMongo from `requirements.txt`.
5. In the Vercel project settings, add these environment variables for **Production**, **Preview**, and **Development** as needed:
   - `MONGODB_URI` — the Atlas connection string. Keep it secret.
   - `MONGODB_DB` — `daybook` (optional; this is the default).
6. Redeploy, open the Vercel URL and create an account.

Never put `MONGODB_URI` in `app.js`, `index.html`, or any other browser-delivered file. The app only uses it inside Python API functions.

## Local development

Install Python 3.12+ and dependencies once:

```powershell
python -m pip install -r requirements.txt
```

Set the same Atlas values in PowerShell, then start the local web server:

```powershell
$env:MONGODB_URI = 'your Atlas connection string'
$env:MONGODB_DB = 'daybook'
python local_server.py
```

Open <http://127.0.0.1:8000>.

## Database collections

The API creates the required indexes on first use. Data is held in `users`, `sessions`, `prayers`, and `quran_sessions` collections. Prayer and Quran records are scoped to the authenticated account ID. Passwords are salted PBKDF2 hashes; session tokens are stored as hashes and sent to the browser only in HTTP-only cookies.

