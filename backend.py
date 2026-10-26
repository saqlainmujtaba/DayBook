"""Shared Daybook API for Vercel functions and the local development server."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import ssl
import threading
import time
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from http import cookies
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from bson import ObjectId
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError
from pymongo.server_api import ServerApi

COOKIE_NAME = "daybook_session"
SESSION_DAYS = 30
PBKDF2_ROUNDS = 310_000
PRAYERS = {"Fajr", "Dhuhr", "Asr", "Maghrib", "Isha"}
MAX_BODY = 32_768
_client = None
_client_lock = threading.Lock()
_indexes_ready = False


def database():
    global _client, _indexes_ready
    uri = os.environ.get("MONGODB_URI")
    if not uri:
        raise RuntimeError("MONGODB_URI is not configured. Add your MongoDB Atlas connection string to the Vercel environment variables.")
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = MongoClient(uri, server_api=ServerApi("1"), connectTimeoutMS=10000, serverSelectionTimeoutMS=10000, appname="Daybook")
    db = _client[os.environ.get("MONGODB_DB", "daybook")]
    if not _indexes_ready:
        with _client_lock:
            if not _indexes_ready:
                db.users.create_index([("email", ASCENDING)], unique=True)
                db.users.create_index([("phone", ASCENDING)], unique=True, sparse=True)
                db.users.create_index([("google_sub", ASCENDING)], unique=True, sparse=True)
                db.users.create_index([("firebase_uid", ASCENDING)], unique=True, sparse=True)
                db.sessions.create_index([("token_hash", ASCENDING)], unique=True)
                db.sessions.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
                db.email_verifications.create_index([("email", ASCENDING)], unique=True)
                db.email_verifications.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
                db.prayers.create_index([("user_id", ASCENDING), ("date", ASCENDING), ("prayer", ASCENDING)], unique=True)
                db.quran_sessions.create_index([("user_id", ASCENDING), ("date", DESCENDING), ("created_at", DESCENDING)])
                _indexes_ready = True
    return db


def valid_date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return False
    try:
        date.fromisoformat(value)
        return True
    except ValueError:
        return False


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    value = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${value.hex()}"


def verify_password(password, stored):
    try:
        scheme, rounds, salt_hex, expected = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)).hex()
        return hmac.compare_digest(got, expected)
    except (ValueError, TypeError, AttributeError):
        return False


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def public_user(user):
    email = user.get("email", "")
    return {"id": str(user["_id"]), "email": "" if email.endswith("@phone.daybook.invalid") else email, "phone": user.get("phone", ""), "name": user.get("name", ""), "identifier": user.get("phone") or email}


def valid_origin(handler):
    origin = handler.headers.get("Origin")
    if not origin:
        return True
    return urlparse(origin).netloc.lower() == handler.headers.get("Host", "").lower()


class ApiMixin:
    endpoint = None

    def log_message(self, fmt, *args):
        print(f"[Daybook] {self.address_string()} {fmt % args}")

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def respond(self, status, payload, cookie_header=None, extra_headers=()):
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        if cookie_header:
            self.send_header("Set-Cookie", cookie_header)
        for key, value in extra_headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def provider_request(self, url, data=None, headers=None):
        request = Request(url, data=data, headers=headers or {})
        try:
            with urlopen(request, timeout=12) as response:
                return json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, ValueError) as error:
            raise ValueError("The sign-in provider could not verify the request. Please try again.") from error

    def read_json(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid request size.")
        if size < 1 or size > MAX_BODY:
            raise ValueError("Request body is empty or too large.")
        try:
            payload = json.loads(self.rfile.read(size).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Send valid JSON.")
        if not isinstance(payload, dict):
            raise ValueError("Send a JSON object.")
        return payload

    def session_cookie(self, token, expiry):
        jar = cookies.SimpleCookie()
        jar[COOKIE_NAME] = token
        jar[COOKIE_NAME]["path"] = "/"
        jar[COOKIE_NAME]["httponly"] = True
        jar[COOKIE_NAME]["samesite"] = "Lax"
        jar[COOKIE_NAME]["max-age"] = str(max(0, expiry - int(time.time())))
        if expiry:
            jar[COOKIE_NAME]["expires"] = datetime.fromtimestamp(expiry, timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        if os.environ.get("VERCEL") or self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip() == "https":
            jar[COOKIE_NAME]["secure"] = True
        return jar[COOKIE_NAME].OutputString()

    def current_user(self, db):
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except cookies.CookieError:
            return None
        morsel = jar.get(COOKIE_NAME)
        if morsel is None:
            return None
        session = db.sessions.find_one({"token_hash": token_hash(morsel.value), "expires_at": {"$gt": datetime.now(timezone.utc)}})
        if not session:
            return None
        return db.users.find_one({"_id": session["user_id"]})

    def _endpoint(self):
        if self.endpoint:
            return self.endpoint
        parts = urlparse(self.path).path.strip("/").split("/")
        return parts[-1] if len(parts) >= 2 and parts[0] == "api" else ""

    def do_GET(self):
        if not self.path.startswith("/api/") and not self.endpoint:
            return super().do_GET()
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_PATCH(self):
        self.dispatch("PATCH")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def dispatch(self, method):
        endpoint = self._endpoint()
        allowed = {
            "me": {"GET"}, "data": {"GET", "DELETE"}, "export": {"GET"},
            "register-code": {"POST"}, "register-verify": {"POST"}, "login": {"POST"}, "logout": {"POST"},
            "profile": {"PATCH"}, "prayers": {"POST"}, "sessions": {"POST"},
            "firebase-login": {"POST"}, "firebase-config": {"GET"}, "phone-verify": {"POST"},
        }
        if method not in allowed.get(endpoint, set()):
            self.respond(404 if endpoint not in allowed else 405, {"error": "API endpoint not found." if endpoint not in allowed else "Method not allowed."})
            return
        if method in {"POST", "PATCH", "DELETE"} and not valid_origin(self):
            self.respond(403, {"error": "Request origin was rejected."})
            return
        try:
            body = self.read_json() if method in {"POST", "PATCH"} else {}
        except ValueError as error:
            self.respond(400, {"error": str(error)})
            return
        try:
            if endpoint == "register-code":
                self.send_registration_code(body); return
            if endpoint == "register-verify":
                self.verify_registration_code(body); return
            if endpoint == "firebase-login":
                self.firebase_login(body); return
            if endpoint == "firebase-config":
                self.firebase_config(); return
            if endpoint == "phone-verify":
                self.verify_phone_code(body); return
            self.perform(endpoint, method, body)
        except Exception as error:
            print(f"[Daybook] API error on {endpoint}: {type(error).__name__}: {error}")
            self.respond(500, {"error": "The request could not be completed. Check the app's database configuration and try again."})

    def perform(self, endpoint, method, body):
        if endpoint == "logout":
            try:
                jar = cookies.SimpleCookie(); jar.load(self.headers.get("Cookie", ""))
                morsel = jar.get(COOKIE_NAME)
                if morsel:
                    database().sessions.delete_one({"token_hash": token_hash(morsel.value)})
            except Exception:
                pass
            self.respond(200, {"ok": True}, self.session_cookie("", 0))
            return

        db = database()
        if endpoint == "login":
            email = str(body.get("email", "")).strip().lower()
            password = body.get("password", "")
            user = db.users.find_one({"email": email})
            if not user or not isinstance(password, str) or not verify_password(password, user.get("password_hash")):
                self.respond(401, {"error": "Email or password is incorrect."}); return
            self.create_session(db, user, 200); return

        if endpoint == "me":
            user = self.current_user(db)
            self.respond(200, {"user": public_user(user) if user else None}); return

        user = self.current_user(db)
        if not user:
            self.respond(401, {"error": "Please sign in again."}); return
        uid = user["_id"]

        if endpoint == "data" and method == "GET":
            prayer_data = {}
            for row in db.prayers.find({"user_id": uid, "prayed": True}, {"_id": 0, "date": 1, "prayer": 1}).sort("date", ASCENDING):
                prayer_data.setdefault(row["date"], []).append(row["prayer"])
            rows = db.quran_sessions.find({"user_id": uid}).sort([("date", DESCENDING), ("created_at", DESCENDING)]).limit(1000)
            sessions = [{"id": str(r["_id"]), "date": r["date"], "surah": r.get("surah", ""), "pages": r["pages"], "minutes": r.get("minutes", 0)} for r in rows]
            self.respond(200, {"user": public_user(user), "prayers": prayer_data, "sessions": sessions}); return

        if endpoint == "export" and method == "GET":
            prayers = list(db.prayers.find({"user_id": uid, "prayed": True}, {"_id": 0, "date": 1, "prayer": 1}).sort("date", ASCENDING))
            sessions = [{"id": str(r["_id"]), "date": r["date"], "surah": r.get("surah", ""), "pages": r["pages"], "minutes": r.get("minutes", 0), "created_at": r["created_at"].isoformat()} for r in db.quran_sessions.find({"user_id": uid}).sort([("date", DESCENDING), ("created_at", DESCENDING)])]
            self.respond(200, {"user": public_user(user), "prayers": prayers, "sessions": sessions, "exportedAt": datetime.now(timezone.utc).isoformat()}); return

        if endpoint == "profile":
            name = body.get("name", "")
            if not isinstance(name, str) or len(name.strip()) > 32:
                self.respond(400, {"error": "Name must be 32 characters or fewer."}); return
            name = name.strip()
            db.users.update_one({"_id": uid}, {"$set": {"name": name}})
            self.respond(200, {"user": {**public_user(user), "name": name}}); return

        if endpoint == "prayers":
            prayer_date, prayer, prayed = body.get("date"), body.get("prayer"), body.get("prayed")
            if not valid_date(prayer_date) or prayer not in PRAYERS or not isinstance(prayed, bool):
                self.respond(400, {"error": "Provide a valid date, prayer and prayed status."}); return
            query = {"user_id": uid, "date": prayer_date, "prayer": prayer}
            if prayed:
                db.prayers.update_one(query, {"$set": {"prayed": True}}, upsert=True)
            else:
                db.prayers.delete_one(query)
            self.respond(200, {"ok": True}); return

        if endpoint == "sessions":
            session_date, pages = body.get("date"), body.get("pages")
            minutes, surah = body.get("minutes", 0), body.get("surah", "")
            if not valid_date(session_date) or type(pages) is not int or not 1 <= pages <= 604 or type(minutes) is not int or not 0 <= minutes <= 1440 or not isinstance(surah, str) or len(surah.strip()) > 60:
                self.respond(400, {"error": "Check the date, surah, pages and minutes and try again."}); return
            result = db.quran_sessions.insert_one({"user_id": uid, "date": session_date, "surah": surah.strip(), "pages": pages, "minutes": minutes, "created_at": datetime.now(timezone.utc)})
            self.respond(201, {"id": str(result.inserted_id), "ok": True}); return

        if endpoint == "data" and method == "DELETE":
            db.prayers.delete_many({"user_id": uid}); db.quran_sessions.delete_many({"user_id": uid})
            self.respond(200, {"ok": True}); return

    def create_session(self, db, user, status):
        token = secrets.token_urlsafe(32)
        expiry = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
        db.sessions.insert_one({"token_hash": token_hash(token), "user_id": user["_id"], "expires_at": expiry})
        self.respond(status, {"user": public_user(user)}, self.session_cookie(token, int(expiry.timestamp())))

    def registration_email(self, value):
        email = str(value or "").strip().lower()
        if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            self.respond(400, {"error": "Enter a valid email address."})
            return None
        return email

    def send_registration_code(self, body):
        email = self.registration_email(body.get("email"))
        if not email:
            return
        password = body.get("password", "")
        name = str(body.get("name", "")).strip()[:32]
        if not isinstance(password, str) or len(password) < 10 or len(password) > 200:
            self.respond(400, {"error": "Use a password between 10 and 200 characters."})
            return
        smtp_email = os.environ.get("SMTP_EMAIL")
        smtp_app_password = os.environ.get("SMTP_APP_PASSWORD")
        otp_secret = os.environ.get("OTP_SECRET")
        if not smtp_email or not smtp_app_password or not otp_secret:
            self.respond(503, {"error": "Email verification is not configured yet. Add the Gmail SMTP and OTP settings to the server."})
            return

        db = database()
        if db.users.find_one({"email": email}):
            self.respond(409, {"error": "An account with that email already exists. Sign in instead."})
            return
        now = datetime.now(timezone.utc)
        pending = db.email_verifications.find_one({"email": email})
        if pending:
            last_sent = pending.get("last_sent_at")
            if last_sent and now - last_sent < timedelta(seconds=60):
                self.respond(429, {"error": "Wait a minute before requesting another code."})
                return
            send_times = [stamp for stamp in pending.get("send_times", []) if now - stamp < timedelta(hours=1)]
            if len(send_times) >= 5:
                self.respond(429, {"error": "Too many codes requested for this email. Try again in an hour."})
                return
        else:
            send_times = []

        code = f"{secrets.randbelow(1_000_000):06d}"
        code_hash = hmac.new(otp_secret.encode(), f"{email}:{code}".encode(), hashlib.sha256).hexdigest()
        expires_at = now + timedelta(minutes=10)
        db.email_verifications.update_one(
            {"email": email},
            {"$set": {"code_hash": code_hash, "name": name, "password_hash": hash_password(password), "created_at": now, "last_sent_at": now, "expires_at": expires_at, "attempts": 0, "send_times": send_times + [now]}},
            upsert=True,
        )
        message = EmailMessage()
        message["From"] = f"Daybook <{smtp_email}>"
        message["To"] = email
        message["Subject"] = "Your Daybook verification code"
        message.set_content(f"Your Daybook verification code is {code}. It expires in 10 minutes. If you did not request this, you can ignore this email.")
        message.add_alternative(
            f"<div style=\"font-family:Arial,sans-serif;max-width:480px;margin:0 auto;color:#21382f\"><h2>Verify your email</h2><p>Enter this code in Daybook to finish creating your account:</p><p style=\"font-size:30px;font-weight:700;letter-spacing:8px\">{code}</p><p>This code expires in 10 minutes. If you did not request it, you can ignore this email.</p></div>",
            subtype="html",
        )
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=12) as smtp:
                smtp.login(smtp_email, smtp_app_password.replace(" ", ""))
                smtp.send_message(message)
        except (smtplib.SMTPException, OSError, ValueError):
            db.email_verifications.delete_one({"email": email, "code_hash": code_hash})
            self.respond(502, {"error": "Could not send the verification email. Check the Gmail address and App Password."})
            return
        self.respond(200, {"ok": True, "message": "If this address can be registered, a verification code has been sent."})

    def verify_registration_code(self, body):
        email = self.registration_email(body.get("email"))
        if not email:
            return
        code = str(body.get("code", "")).strip()
        if not re.fullmatch(r"\d{6}", code):
            self.respond(400, {"error": "Enter the six-digit code from your email."})
            return
        otp_secret = os.environ.get("OTP_SECRET")
        if not otp_secret:
            self.respond(503, {"error": "Email verification is not configured yet."})
            return
        db = database()
        pending = db.email_verifications.find_one({"email": email})
        now = datetime.now(timezone.utc)
        if not pending or pending.get("expires_at") <= now:
            if pending:
                db.email_verifications.delete_one({"_id": pending["_id"]})
            self.respond(400, {"error": "That code expired. Request a new one and try again."})
            return
        if pending.get("attempts", 0) >= 5:
            db.email_verifications.delete_one({"_id": pending["_id"]})
            self.respond(429, {"error": "Too many incorrect attempts. Request a new code."})
            return
        expected = hmac.new(otp_secret.encode(), f"{email}:{code}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, pending.get("code_hash", "")):
            db.email_verifications.update_one({"_id": pending["_id"]}, {"$inc": {"attempts": 1}})
            self.respond(401, {"error": "That code is incorrect. Check it and try again."})
            return
        if db.users.find_one({"email": email}):
            db.email_verifications.delete_one({"_id": pending["_id"]})
            self.respond(409, {"error": "An account with that email already exists. Sign in instead."})
            return
        try:
            user_id = db.users.insert_one({"email": email, "name": pending.get("name", ""), "password_hash": pending["password_hash"], "email_verified": True, "created_at": now}).inserted_id
        except DuplicateKeyError:
            db.email_verifications.delete_one({"_id": pending["_id"]})
            self.respond(409, {"error": "An account with that email already exists. Sign in instead."})
            return
        db.email_verifications.delete_one({"_id": pending["_id"]})
        self.create_session(db, db.users.find_one({"_id": user_id}), 201)

    def firebase_config(self):
        keys = {"apiKey": "FIREBASE_API_KEY", "authDomain": "FIREBASE_AUTH_DOMAIN", "projectId": "FIREBASE_PROJECT_ID", "appId": "FIREBASE_APP_ID"}
        config = {key: os.environ.get(env, "") for key, env in keys.items()}
        if not all(config.values()):
            self.respond(503, {"error": "Firebase sign-in is not configured yet."}); return
        self.respond(200, {"config": config})

    def firebase_identity(self, body):
        id_token = body.get("idToken")
        api_key = os.environ.get("FIREBASE_API_KEY")
        if not isinstance(id_token, str) or not id_token or len(id_token) > 8192:
            self.respond(400, {"error": "Complete Firebase sign-in and try again."}); return None
        if not api_key:
            self.respond(503, {"error": "Firebase sign-in is not configured yet."}); return None
        try:
            result = self.provider_request("https://identitytoolkit.googleapis.com/v1/accounts:lookup?" + urlencode({"key": api_key}), json.dumps({"idToken": id_token}).encode(), {"Content-Type": "application/json"})
        except ValueError:
            self.respond(401, {"error": "Firebase sign-in expired or could not be confirmed. Please try again."}); return None
        firebase_users = result.get("users", [])
        if len(firebase_users) != 1 or not firebase_users[0].get("localId"):
            self.respond(401, {"error": "Firebase sign-in could not be confirmed. Please try again."}); return None
        return firebase_users[0]

    def verify_phone_code(self, body):
        firebase_user = self.firebase_identity(body)
        if not firebase_user:
            return
        if not re.fullmatch(r"\+[1-9]\d{7,14}", str(firebase_user.get("phoneNumber", ""))):
            self.respond(401, {"error": "Phone sign-in could not be confirmed. Please try again."}); return
        phone, firebase_uid = firebase_user["phoneNumber"], firebase_user["localId"]
        db = database()
        user = db.users.find_one({"firebase_uid": firebase_uid}) or db.users.find_one({"phone": phone})
        if not user:
            synthetic_email = "phone+" + hashlib.sha256(phone.encode()).hexdigest() + "@phone.daybook.invalid"
            try:
                result = db.users.insert_one({"email": synthetic_email, "phone": phone, "firebase_uid": firebase_uid, "name": "", "created_at": datetime.now(timezone.utc)})
                user = db.users.find_one({"_id": result.inserted_id})
            except DuplicateKeyError:
                user = db.users.find_one({"firebase_uid": firebase_uid}) or db.users.find_one({"phone": phone})
        elif not user.get("firebase_uid"):
            db.users.update_one({"_id": user["_id"], "firebase_uid": {"$exists": False}}, {"$set": {"firebase_uid": firebase_uid}})
            user = db.users.find_one({"_id": user["_id"]})
        if not user:
            self.respond(409, {"error": "Could not create your account. Please try again."}); return
        self.create_session(db, user, 200)

    def firebase_login(self, body):
        firebase_user = self.firebase_identity(body)
        if not firebase_user:
            return
        email = str(firebase_user.get("email", "")).strip().lower()
        providers = firebase_user.get("providerUserInfo", [])
        google_signin = any(provider.get("providerId") == "google.com" for provider in providers)
        if not google_signin or firebase_user.get("emailVerified") is not True or not email:
            self.respond(401, {"error": "Verified Google sign-in could not be confirmed."}); return
        uid = firebase_user["localId"]
        db = database()
        user = db.users.find_one({"firebase_uid": uid}) or db.users.find_one({"email": email})
        if user:
            if user.get("firebase_uid") and user["firebase_uid"] != uid:
                self.respond(409, {"error": "This email belongs to a different sign-in account."}); return
            db.users.update_one({"_id": user["_id"], "firebase_uid": {"$exists": False}}, {"$set": {"firebase_uid": uid, "name": user.get("name") or str(firebase_user.get("displayName", ""))[:32]}})
            user = db.users.find_one({"_id": user["_id"]})
        else:
            try:
                inserted = db.users.insert_one({"email": email, "firebase_uid": uid, "name": str(firebase_user.get("displayName", ""))[:32], "created_at": datetime.now(timezone.utc)})
                user = db.users.find_one({"_id": inserted.inserted_id})
            except DuplicateKeyError:
                user = db.users.find_one({"firebase_uid": uid}) or db.users.find_one({"email": email})
        if not user:
            self.respond(409, {"error": "Could not create your account. Please try again."}); return
        if user.get("firebase_uid") != uid:
            db.users.update_one({"_id": user["_id"], "firebase_uid": {"$exists": False}}, {"$set": {"firebase_uid": uid}})
            user = db.users.find_one({"_id": user["_id"]})
        if user.get("firebase_uid") != uid:
            self.respond(409, {"error": "This email belongs to a different sign-in account."}); return
        self.create_session(db, user, 200)


class handler(ApiMixin, BaseHTTPRequestHandler):
    """Vercel Python function base class. Endpoint subclasses set `endpoint`."""
    pass
