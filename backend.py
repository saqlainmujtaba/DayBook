"""Shared Daybook API for Vercel functions and the local development server."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import date, datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

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
                db.sessions.create_index([("token_hash", ASCENDING)], unique=True)
                db.sessions.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
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
    return {"id": str(user["_id"]), "email": user["email"], "name": user.get("name", "")}


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
            "register": {"POST"}, "login": {"POST"}, "logout": {"POST"},
            "profile": {"PATCH"}, "prayers": {"POST"}, "sessions": {"POST"},
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
        if endpoint == "register":
            email = str(body.get("email", "")).strip().lower()
            password = body.get("password", "")
            name = str(body.get("name", "")).strip()[:32]
            if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                self.respond(400, {"error": "Enter a valid email address."}); return
            if not isinstance(password, str) or len(password) < 10 or len(password) > 200:
                self.respond(400, {"error": "Use a password between 10 and 200 characters."}); return
            try:
                user_id = db.users.insert_one({"email": email, "name": name, "password_hash": hash_password(password), "created_at": datetime.now(timezone.utc)}).inserted_id
            except DuplicateKeyError:
                self.respond(409, {"error": "An account with that email already exists. Sign in instead."}); return
            user = db.users.find_one({"_id": user_id})
            self.create_session(db, user, 201); return

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
            self.respond(200, {"user": {"id": str(uid), "email": user["email"], "name": name}}); return

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


class handler(ApiMixin, BaseHTTPRequestHandler):
    """Vercel Python function base class. Endpoint subclasses set `endpoint`."""
    pass
