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

### Google and phone sign-in

- Google: enable the Google provider under Firebase Authentication’s sign-in providers. The same Firebase web app config used for phone sign-in powers Google sign-in, so Daybook does not need a separate Google OAuth client or Google client secrets. Ensure your deployed domain is listed under Firebase Authentication’s authorized domains.
- Phone: create a Firebase project and web app, enable Phone Number sign-in in Firebase Authentication, authorize your Vercel domain, and allow the SMS regions you want to support. Set `FIREBASE_API_KEY`, `FIREBASE_AUTH_DOMAIN`, `FIREBASE_PROJECT_ID`, and `FIREBASE_APP_ID` in Vercel from the Firebase web app config. Firebase handles reCAPTCHA and SMS verification; Daybook validates the resulting Firebase ID token before opening its own session. Firebase currently does not bill the first 10 verification SMS sent per day, but production phone auth requires a billing account and additional SMS can be charged.
- Add these values to the relevant Vercel environments and redeploy. Google and phone sign-in use the shared Firebase config. Firebase phone sign-in requires an authorized web domain; use a deployed authorized domain for phone testing.

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

The API creates the required indexes on first use. Data is held in `users`, `sessions`, `prayers`, and `quran_sessions` collections. Prayer and Quran records are scoped to the authenticated account ID. Passwords are salted PBKDF2 hashes; session tokens are stored as hashes and sent to the browser only in HTTP-only cookies. Google and phone accounts use Firebase user IDs, and phone accounts are created only after Firebase verifies the number.

