# -*- coding: utf-8 -*-
"""
RestTime License Server (보안 강화판)
=====================================
사용자 프로그램(RestTime.exe)과 관리자 프로그램(RestTime Admin.exe)이
공통으로 통신하는 라이선스 발급/검증 서버.

- 사용자 API: /license/*   (장치 기반, 코드 자체가 비밀 + 요청 횟수 제한 + 재사용 방지)
- 관리자 API: /admin/*     (로그인 + 서버에서 폐기 가능한 세션 토큰 + 감사 기록)

보안 설계 요약 (자세한 내용은 '보안_구현_현황.md'):
- 라이선스의 유효성/만료/장치 등록은 항상 서버 DB 기준 (클라이언트 시계/파일을 믿지 않음)
- 응답에 서버 개인키로 서명한 'lease'를 넣어 가짜 서버/응답 재사용을 막음 (LICENSE_SIGNING_KEY 설정 시)
- 요청 횟수 제한은 DB에 저장해서 서버가 여러 개로 뜨거나 재시작돼도 유지됨
- 관리자 로그인 실패 제한/지연, 토큰 폐기, 중요 작업 비밀번호 재확인(선택), 감사 기록

실행:
    pip install -r requirements.txt
    python app.py
"""

import os
import re
import ssl
import json
import time
import base64
import random
import sqlite3
import secrets
import hashlib
import calendar
import datetime
import functools
import urllib.parse

from flask import Flask, request, jsonify, g
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from dateutil.relativedelta import relativedelta
import jwt

# ---------------------------------------------------------------------------
# 설정 (모두 환경변수. 코드에 비밀값을 넣지 않는다)
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "license.db")

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
USE_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


IS_RENDER = bool(os.environ.get("RENDER"))
# 프록시 뒤에서 실제 접속자 IP를 X-Forwarded-For에서 읽을지 (Render는 기본 켬)
TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "1" if IS_RENDER else "0") == "1"
# HTTPS가 아닌 요청 차단 (Render는 기본 켬)
ENFORCE_HTTPS = os.environ.get("ENFORCE_HTTPS", "1" if IS_RENDER else "0") == "1"
# 1이면 nonce/ts 없는 라이선스 요청을 거부 (모든 사용자가 새 앱으로 바꾼 뒤에 켜기)
REQUIRE_NONCE = os.environ.get("REQUIRE_NONCE") == "1"
# 1이면 폐기/삭제/장치해제/백업 같은 중요 작업에 관리자 비밀번호 재입력 요구
ADMIN_REAUTH_REQUIRED = os.environ.get("ADMIN_REAUTH_REQUIRED") == "1"
ADMIN_TOKEN_HOURS = _env_int("ADMIN_TOKEN_HOURS", 4)
LOGIN_FAIL_DELAY = float(os.environ.get("LOGIN_FAIL_DELAY", "0.4"))
FRESHNESS_WINDOW_SEC = _env_int("FRESHNESS_WINDOW_SEC", 300)

# (창 길이(초), 허용 횟수)
RATE = {
    "validate_ip": (600, _env_int("RL_VALIDATE_IP", 600)),
    "validate_code": (600, _env_int("RL_VALIDATE_CODE", 60)),
    "activate_ip": (600, _env_int("RL_ACTIVATE_IP", 30)),
    "activate_code": (600, _env_int("RL_ACTIVATE_CODE", 10)),
    "admin_api": (600, _env_int("RL_ADMIN_API", 600)),
    "login_fail_pair": (900, _env_int("RL_LOGIN_FAIL_PAIR", 5)),
    "login_fail_ip": (900, _env_int("RL_LOGIN_FAIL_IP", 20)),
    "login_fail_user": (3600, _env_int("RL_LOGIN_FAIL_USER", 30)),
    "reauth_fail": (900, _env_int("RL_REAUTH_FAIL", 5)),
}

JWT_SECRET = os.environ.get("RESTTIME_JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError(
        "환경변수 RESTTIME_JWT_SECRET 이 설정되지 않았습니다.\n"
        "예: export RESTTIME_JWT_SECRET=$(python -c \"import secrets;print(secrets.token_hex(32))\")"
    )

DEFAULT_GRACE_PERIOD_DAYS = 3

LICENSE_TYPES = {
    "1day": {"label": "1 Day", "delta": lambda: relativedelta(days=1)},
    "7day": {"label": "7 Days", "delta": lambda: relativedelta(days=7)},
    "1month": {"label": "1 Month", "delta": lambda: relativedelta(months=1)},
    "1year": {"label": "1 Year", "delta": lambda: relativedelta(years=1)},
    "lifetime": {"label": "Lifetime", "delta": None},
}

# 서명 키 (Ed25519 개인키 32바이트의 base64). 없으면 '서명 없는 호환 모드'로 동작한다.
SIGNING_KEY = None
SIGNING_PUBLIC_B64 = ""
_sk_raw = os.environ.get("LICENSE_SIGNING_KEY", "").strip()
if _sk_raw:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(base64.b64decode(_sk_raw))
        SIGNING_PUBLIC_B64 = base64.b64encode(
            SIGNING_KEY.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode()
    except Exception as _e:  # 키 내용은 절대 출력하지 않는다
        raise RuntimeError(
            "LICENSE_SIGNING_KEY 형식이 올바르지 않습니다 (tools/gen_keys.py 로 만든 값을 그대로 넣으세요): "
            + type(_e).__name__
        )

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 요청 본문 최대 16KB
app.config["JSON_AS_ASCII"] = False


# ---------------------------------------------------------------------------
# DB 계층 (SQLite / Postgres 겸용)
# ---------------------------------------------------------------------------

class _PgCursor:
    def __init__(self, cur):
        self._cur = cur
        self._cols = [d[0] for d in cur.description] if cur.description else []

    def fetchone(self):
        if not self._cols:
            return None
        row = self._cur.fetchone()
        return dict(zip(self._cols, row)) if row is not None else None

    def fetchall(self):
        if not self._cols:
            return []
        return [dict(zip(self._cols, r)) for r in self._cur.fetchall()]


class _PgConn:
    """pg8000(Postgres) 연결을 sqlite3 연결처럼(execute/commit/rollback/close) 쓰게 해주는 어댑터."""

    def __init__(self, raw):
        self._raw = raw

    def execute(self, sql, params=()):
        cur = self._raw.cursor()
        cur.execute(sql.replace("?", "%s"), tuple(params))
        return _PgCursor(cur)

    def commit(self):
        self._raw.commit()

    def rollback(self):
        try:
            self._raw.rollback()
        except Exception:
            pass

    def close(self):
        try:
            self._raw.close()
        except Exception:
            pass


def _pg_connect():
    import pg8000.dbapi

    u = urllib.parse.urlparse(DATABASE_URL)
    qs = urllib.parse.parse_qs(u.query)
    host = u.hostname
    if host and ".neon.tech" in host:
        host = host.replace("-pooler", "")
    sslmode = (qs.get("sslmode", [""])[0] or "").lower()
    if sslmode == "disable" or (not sslmode and host in ("localhost", "127.0.0.1", "::1")):
        ctx = None
    else:
        ctx = ssl.create_default_context()
    raw = pg8000.dbapi.connect(
        user=urllib.parse.unquote(u.username or ""),
        password=urllib.parse.unquote(u.password or ""),
        host=host,
        port=u.port or 5432,
        database=(u.path or "/").lstrip("/") or "postgres",
        ssl_context=ctx,
        timeout=20,
    )
    return _PgConn(raw)


def _connect():
    if USE_PG:
        return _pg_connect()
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    if "db" not in g:
        g.db = _connect()
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


LICENSE_COLS = [
    "license_id", "code_hash", "code_display", "license_type", "created_at", "activated_at",
    "first_activated_at", "expires_at", "status", "device_id", "device_first_seen",
    "last_validated_at", "memo",
]
AUDIT_COLS = ["id", "ts", "category", "actor", "action", "target", "ip", "detail"]

_DDL = [
    """CREATE TABLE IF NOT EXISTS licenses (
        license_id          TEXT PRIMARY KEY,
        code_hash           TEXT UNIQUE NOT NULL,
        code_display        TEXT NOT NULL,
        license_type        TEXT NOT NULL,
        created_at          TEXT NOT NULL,
        activated_at        TEXT,
        first_activated_at  TEXT,
        expires_at          TEXT,
        status              TEXT NOT NULL DEFAULT 'available',
        device_id           TEXT,
        device_first_seen   TEXT,
        last_validated_at   TEXT,
        memo                TEXT NOT NULL DEFAULT ''
    )""",
    """CREATE TABLE IF NOT EXISTS admins (
        username      TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT
    )""",
    # 요청 횟수 제한 카운터 (서버가 여러 개여도/재시작해도 유지되도록 DB에 저장)
    """CREATE TABLE IF NOT EXISTS rate_limits (
        bucket       TEXT NOT NULL,
        window_start BIGINT NOT NULL,
        count        INTEGER NOT NULL,
        PRIMARY KEY (bucket, window_start)
    )""",
    # 재전송 공격 방지용 nonce
    """CREATE TABLE IF NOT EXISTS used_nonces (
        nonce      TEXT PRIMARY KEY,
        expires_at BIGINT NOT NULL
    )""",
    # 관리자 세션 (서버에서 폐기 가능)
    """CREATE TABLE IF NOT EXISTS admin_sessions (
        jti        TEXT PRIMARY KEY,
        username   TEXT NOT NULL,
        issued_at  BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        revoked    INTEGER NOT NULL DEFAULT 0,
        ip         TEXT
    )""",
    # 감사/보안 기록 (민감정보 평문 저장 금지)
    """CREATE TABLE IF NOT EXISTS audit_log (
        id       TEXT PRIMARY KEY,
        ts       BIGINT NOT NULL,
        category TEXT NOT NULL,
        actor    TEXT,
        action   TEXT NOT NULL,
        target   TEXT,
        ip       TEXT,
        detail   TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts)",
]


def init_db():
    conn = _connect()
    try:
        if USE_PG:
            # 서버 워커가 동시에 부팅하며 테이블을 만들 때의 충돌을 막는 advisory lock
            conn.execute("SELECT pg_advisory_xact_lock(727272)")
        for ddl in _DDL:
            conn.execute(ddl)
        if USE_PG:
            conn.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS memo TEXT NOT NULL DEFAULT ''")
        else:
            try:
                conn.execute("ALTER TABLE licenses ADD COLUMN memo TEXT NOT NULL DEFAULT ''")
            except sqlite3.OperationalError:
                pass
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING",
            ("grace_period_days", str(DEFAULT_GRACE_PERIOD_DAYS)),
        )

        seed_user = os.environ.get("ADMIN_USERNAME")
        seed_pass = os.environ.get("ADMIN_PASSWORD")
        if seed_user and seed_pass:
            if os.environ.get("ADMIN_PASSWORD_RESET") == "1":
                conn.execute(
                    "INSERT INTO admins (username, password_hash) VALUES (?, ?) "
                    "ON CONFLICT (username) DO UPDATE SET password_hash = excluded.password_hash",
                    (seed_user, generate_password_hash(seed_pass)),
                )
            else:
                conn.execute(
                    "INSERT INTO admins (username, password_hash) VALUES (?, ?) "
                    "ON CONFLICT (username) DO NOTHING",
                    (seed_user, generate_password_hash(seed_pass)),
                )
            if len(seed_pass) < 10:
                print("[RestTime][경고] 관리자 비밀번호가 짧습니다. 10자 이상(영문+숫자+기호 섞기)을 권장합니다.", flush=True)
        conn.commit()
    finally:
        conn.close()


def get_setting(key, default=None):
    row = get_db().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


if len(JWT_SECRET) < 24:
    print("[RestTime][경고] RESTTIME_JWT_SECRET 이 짧습니다. 32자 이상의 랜덤 문자열을 권장합니다.", flush=True)
print(f"[RestTime] 데이터 저장소: {'외부 Postgres (영구 보존)' if USE_PG else '로컬 SQLite 파일'}", flush=True)
print(f"[RestTime] 라이선스 서명: {'켜짐' if SIGNING_KEY else '꺼짐(호환 모드 - LICENSE_SIGNING_KEY 설정 권장)'}", flush=True)
init_db()


# ---------------------------------------------------------------------------
# 유틸
# ---------------------------------------------------------------------------

DUMMY_HASH = generate_password_hash("restime-dummy-password-for-timing")

RE_CODE = re.compile(r"^RTM-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$")
RE_DEVICE = re.compile(r"^[0-9a-f]{16,64}$")
RE_LICENSE_ID = re.compile(r"^[0-9a-f]{16}$")
RE_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def now_iso():
    return datetime.datetime.utcnow().isoformat()


def iso_to_epoch(s):
    """서버가 저장한 UTC 시각 문자열 -> epoch 초"""
    if not s:
        return None
    return calendar.timegm(datetime.datetime.fromisoformat(s).timetuple())


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def generate_license_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    groups = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "RTM-" + "-".join(groups)


def mask_code(code: str) -> str:
    parts = code.split("-")
    if len(parts) < 2:
        return code
    return parts[0] + "-****-****-" + parts[-1]


def compute_expiry(license_type: str, from_time: datetime.datetime):
    delta_fn = LICENSE_TYPES[license_type]["delta"]
    if delta_fn is None:
        return None
    return from_time + delta_fn()


def compute_live_status(row) -> str:
    status = row["status"]
    if status == "disabled":
        return "disabled"
    if row["expires_at"]:
        expires_at = datetime.datetime.fromisoformat(row["expires_at"])
        if datetime.datetime.utcnow() >= expires_at:
            return "expired"
    if row["device_id"]:
        return "in_use"
    return "available"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _clean(s, n=64):
    """로그/기록에 넣을 문자열에서 제어문자 제거 + 길이 제한 (기록 오염 방지)"""
    s = "".join(ch for ch in str(s) if ch.isprintable())
    return s[:n]


def json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def err(message, status, code=None, **extra):
    body = {"error": message}
    if code:
        body["code"] = code
    body.update(extra)
    resp = jsonify(body)
    resp.status_code = status
    return resp


def client_ip():
    if TRUST_PROXY_HEADERS:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return _clean(xff.split(",")[0].strip(), 45) or "?"
    return _clean(request.remote_addr or "?", 45)


# ---------------------------------------------------------------------------
# 감사 / 보안 기록
# ---------------------------------------------------------------------------

def audit(action, target="", detail="", actor=None, category="admin", commit=True):
    """관리 작업/보안 이벤트 기록. 코드 원문, 비밀번호, 토큰은 절대 넣지 않는다."""
    try:
        db = get_db()
        who = actor if actor is not None else getattr(g, "admin_user", None)
        db.execute(
            "INSERT INTO audit_log (id, ts, category, actor, action, target, ip, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (secrets.token_hex(8), int(time.time()), category, _clean(who or "-", 64),
             _clean(action, 48), _clean(target, 64), client_ip(), _clean(detail, 200)),
        )
        if commit:
            db.commit()
    except Exception as e:
        print(f"[RestTime] 기록 저장 실패: {type(e).__name__}", flush=True)


def sec_event(action, detail="", target=""):
    print(f"[SECURITY] {action} ip={client_ip()} {_clean(detail, 120)}", flush=True)
    audit(action, target=target, detail=detail, actor="-", category="security")


# ---------------------------------------------------------------------------
# 요청 횟수 제한 (DB 저장 - 서버가 여러 개여도/재시작해도 유지)
# ---------------------------------------------------------------------------

def _rl_incr(bucket, window):
    now = int(time.time())
    win = now - (now % window)
    db = get_db()
    sql = ("INSERT INTO rate_limits (bucket, window_start, count) VALUES (?, ?, 1) "
           "ON CONFLICT (bucket, window_start) DO UPDATE SET count = rate_limits.count + 1")
    try:
        row = db.execute(sql + " RETURNING count", (bucket, win)).fetchone()
        db.commit()
        cnt = row["count"]
    except sqlite3.OperationalError:  # RETURNING 미지원 구버전 SQLite 대비
        db.execute(sql, (bucket, win))
        row = db.execute("SELECT count FROM rate_limits WHERE bucket = ? AND window_start = ?",
                         (bucket, win)).fetchone()
        db.commit()
        cnt = row["count"]
    return cnt, (win + window - now)


def rl_count(bucket, window):
    now = int(time.time())
    win = now - (now % window)
    row = get_db().execute("SELECT count FROM rate_limits WHERE bucket = ? AND window_start = ?",
                           (bucket, win)).fetchone()
    return row["count"] if row else 0


def rl_hit(kind, ident):
    """요청 1건을 센다. (허용여부, 재시도까지 남은 초) 반환"""
    window, limit = RATE[kind]
    cnt, retry = _rl_incr(f"{kind}:{ident}", window)
    return cnt <= limit, retry


def rate_limited_response(retry, what="요청"):
    resp = err(f"{what}이 너무 많습니다. 잠시 후 다시 시도해주세요.", 429, "rate_limited", retry_after=retry)
    resp.headers["Retry-After"] = str(max(1, retry))
    return resp


def maybe_cleanup():
    """오래된 카운터/nonce/세션/기록을 가끔(약 1%) 정리한다."""
    if random.random() > 0.01:
        return
    try:
        db = get_db()
        now = int(time.time())
        db.execute("DELETE FROM rate_limits WHERE window_start < ?", (now - 86400,))
        db.execute("DELETE FROM used_nonces WHERE expires_at < ?", (now,))
        db.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (now - 86400,))
        db.execute("DELETE FROM audit_log WHERE ts < ?", (now - 365 * 86400,))
        db.commit()
    except Exception as e:
        print(f"[RestTime] 정리 작업 실패: {type(e).__name__}", flush=True)


# ---------------------------------------------------------------------------
# 입력 검증 / 재전송 방지 / 서명
# ---------------------------------------------------------------------------

def normalize_code(v):
    if not isinstance(v, str):
        return None
    c = v.strip().upper()
    return c if RE_CODE.match(c) else None


def normalize_device(v):
    if not isinstance(v, str):
        return None
    d = v.strip().lower()
    return d if RE_DEVICE.match(d) else None


def check_freshness(data):
    """요청의 ts/nonce를 검사한다. (오류응답 또는 None, nonce 문자열) 반환.
    - 둘 다 없으면: REQUIRE_NONCE가 꺼져 있을 때만 허용(구버전 앱 호환)
    - 있으면: 시간 차이가 허용 범위 안이고, 한 번도 쓰인 적 없는 nonce여야 함"""
    ts, nonce = data.get("ts"), data.get("nonce")
    if ts is None and nonce is None:
        if REQUIRE_NONCE:
            return err("앱을 최신 버전으로 업데이트해주세요.", 400, "nonce_required"), ""
        return None, ""
    if not isinstance(nonce, str) or not RE_NONCE.match(nonce) or isinstance(ts, bool) \
            or not isinstance(ts, (int, float)):
        return err("잘못된 요청입니다.", 400, "invalid_request"), ""
    if abs(time.time() - float(ts)) > FRESHNESS_WINDOW_SEC:
        sec_event("stale_request", "요청 시각이 허용 범위를 벗어남")
        return err("PC의 시간이 서버와 너무 많이 다릅니다. 시간을 확인해주세요.", 400, "stale_request"), ""
    db = get_db()
    row = db.execute(
        "INSERT INTO used_nonces (nonce, expires_at) VALUES (?, ?) ON CONFLICT (nonce) DO NOTHING RETURNING nonce",
        (nonce, int(time.time()) + FRESHNESS_WINDOW_SEC * 2),
    ).fetchone()
    db.commit()
    if row is None:
        sec_event("replay_detected", "이미 사용된 nonce")
        return err("이미 처리된 요청입니다.", 409, "replay_detected"), ""
    return None, nonce


def sign_token(payload: dict):
    """payload를 서버 개인키로 서명한 'payload.signature' 문자열. 키가 없으면 None."""
    if SIGNING_KEY is None:
        return None
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return b64u(body) + "." + b64u(SIGNING_KEY.sign(body))


def make_lease(row, device_id, nonce):
    """클라이언트가 오프라인 유예기간 동안 믿을 수 있는, 서버가 서명한 증명서."""
    if SIGNING_KEY is None:
        return None
    now = int(time.time())
    grace_days = int(get_setting("grace_period_days", DEFAULT_GRACE_PERIOD_DAYS))
    exp = iso_to_epoch(row["expires_at"])
    until = now + grace_days * 86400
    if exp is not None:
        until = min(until, exp)
    return sign_token({
        "v": 1, "lic": row["license_id"], "dev": hashlib.sha256(device_id.encode()).hexdigest()[:16],
        "type": row["license_type"], "exp": exp, "iat": now, "until": until, "nonce": nonce,
    })


# ---------------------------------------------------------------------------
# 관리자 인증 (서버에서 폐기 가능한 세션)
# ---------------------------------------------------------------------------

def issue_admin_session(username):
    now = int(time.time())
    exp = now + ADMIN_TOKEN_HOURS * 3600
    jti = secrets.token_urlsafe(16)
    db = get_db()
    db.execute(
        "INSERT INTO admin_sessions (jti, username, issued_at, expires_at, revoked, ip) VALUES (?, ?, ?, ?, 0, ?)",
        (jti, username, now, exp, client_ip()),
    )
    db.commit()
    token = jwt.encode({"sub": username, "role": "admin", "jti": jti, "iat": now, "exp": exp},
                       JWT_SECRET, algorithm="HS256")
    return token, ADMIN_TOKEN_HOURS * 3600


def require_admin(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or len(auth) > 2100:
            return err("인증 토큰이 필요합니다.", 401, "auth_required")
        token = auth[7:].strip()
        try:
            claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], leeway=10,
                                options={"require": ["exp", "iat", "sub", "jti"]})
        except jwt.ExpiredSignatureError:
            return err("로그인이 만료되었습니다. 다시 로그인하세요.", 401, "auth_expired")
        except jwt.InvalidTokenError:
            sec_event("admin_api_bad_token", "유효하지 않은 토큰으로 관리자 API 접근")
            return err("유효하지 않은 인증입니다.", 401, "auth_invalid")
        if claims.get("role") != "admin":
            sec_event("admin_api_wrong_role", "관리자 권한이 없는 토큰으로 접근")
            return err("유효하지 않은 인증입니다.", 401, "auth_invalid")
        db = get_db()
        sess = db.execute("SELECT revoked, expires_at, username FROM admin_sessions WHERE jti = ?",
                          (claims["jti"],)).fetchone()
        if sess is None or sess["revoked"] or sess["expires_at"] < int(time.time()) \
                or sess["username"] != claims["sub"]:
            return err("로그인이 해제되었습니다. 다시 로그인하세요.", 401, "auth_revoked")
        if db.execute("SELECT 1 FROM admins WHERE username = ?", (claims["sub"],)).fetchone() is None:
            return err("로그인이 해제되었습니다. 다시 로그인하세요.", 401, "auth_revoked")
        g.admin_user = claims["sub"]
        g.admin_jti = claims["jti"]
        ok, retry = rl_hit("admin_api", claims["jti"])
        if not ok:
            return rate_limited_response(retry)
        return fn(*args, **kwargs)

    return wrapper


def require_reauth(data):
    """중요 작업의 비밀번호 재확인. ADMIN_REAUTH_REQUIRED=1 일 때만 강제. 통과 시 None."""
    if not ADMIN_REAUTH_REQUIRED:
        return None
    pw = data.get("password")
    if not isinstance(pw, str) or not pw or len(pw) > 256:
        return err("보안을 위해 비밀번호를 한 번 더 입력해주세요.", 403, "reauth_required")
    if rl_count(f"reauth_fail:{g.admin_user}", RATE["reauth_fail"][0]) >= RATE["reauth_fail"][1]:
        sec_event("reauth_locked", f"user={g.admin_user}")
        return rate_limited_response(300, "재확인 시도")
    row = get_db().execute("SELECT password_hash FROM admins WHERE username = ?", (g.admin_user,)).fetchone()
    if row is None or not check_password_hash(row["password_hash"], pw):
        _rl_incr(f"reauth_fail:{g.admin_user}", RATE["reauth_fail"][0])
        sec_event("reauth_failed", f"user={g.admin_user}")
        time.sleep(LOGIN_FAIL_DELAY)
        return err("비밀번호가 올바르지 않습니다.", 401, "reauth_failed")
    return None


# ---------------------------------------------------------------------------
# 공통 훅 / 오류 처리
# ---------------------------------------------------------------------------

@app.before_request
def _guard():
    if ENFORCE_HTTPS and request.headers.get("X-Forwarded-Proto", "https").lower() == "http":
        return err("HTTPS로만 접속할 수 있습니다.", 403, "https_required")
    maybe_cleanup()


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["X-Frame-Options"] = "DENY"
    if request.headers.get("X-Forwarded-Proto", "").lower() == "https" or request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


_HTTP_MESSAGES = {
    400: "잘못된 요청입니다.", 404: "찾을 수 없습니다.", 405: "허용되지 않는 요청 방식입니다.",
    413: "요청 내용이 너무 큽니다.", 415: "지원하지 않는 형식입니다.",
}


@app.errorhandler(HTTPException)
def _http_error(e):
    return err(_HTTP_MESSAGES.get(e.code, "요청을 처리할 수 없습니다."), e.code or 400)


@app.errorhandler(Exception)
def _unhandled(e):
    # 내부 경로/쿼리/비밀값이 응답에 새지 않도록 종류만 기록하고 일반 메시지만 돌려준다.
    print(f"[RestTime] 처리되지 않은 오류: {type(e).__name__}", flush=True)
    return err("서버 오류가 발생했습니다. 잠시 후 다시 시도해주세요.", 500, "server_error")


# ---------------------------------------------------------------------------
# 상태 / 공식 배포 정보
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    try:
        get_db().execute("SELECT 1").fetchone()
        ok = True
    except Exception as e:
        print(f"[RestTime] health check 실패: {type(e).__name__}", flush=True)
        ok = False
    return jsonify({
        "ok": ok, "db": "postgres" if USE_PG else "sqlite",
        "signing": SIGNING_KEY is not None, "public_key": SIGNING_PUBLIC_B64,
    }), (200 if ok else 503)


@app.get("/app/latest")
def app_latest():
    """공식 최신 버전 정보(서명된 매니페스트). 앱은 이 서명을 검증한 뒤에만 신뢰한다."""
    ver = os.environ.get("RELEASE_VERSION", "").strip()
    url = os.environ.get("RELEASE_URL", "").strip()
    sha = os.environ.get("RELEASE_SHA256", "").strip().lower()
    if not (ver and url and sha) or not url.startswith("https://") or not re.match(r"^[0-9a-f]{64}$", sha):
        return jsonify({"available": False})
    manifest = sign_token({
        "product": "RestTime", "version": ver[:20], "url": url[:300], "sha256": sha,
        "notes": os.environ.get("RELEASE_NOTES", "")[:500], "ts": int(time.time()),
    })
    return jsonify({"available": True, "signed": manifest is not None, "manifest": manifest})


# ---------------------------------------------------------------------------
# 사용자 API
# ---------------------------------------------------------------------------

@app.post("/license/activate")
def activate_license():
    ip = client_ip()
    ok, retry = rl_hit("activate_ip", ip)
    if not ok:
        sec_event("rate_limited_activate_ip", "활성화 요청 과다")
        return rate_limited_response(retry)

    data = json_body()
    bad, nonce = check_freshness(data)
    if bad is not None:
        return bad

    code = normalize_code(data.get("code"))
    device_id = normalize_device(data.get("device_id"))
    if not device_id:
        return err("잘못된 요청입니다.", 400, "invalid_request")
    if not code:
        return err("존재하지 않는 라이선스 코드입니다.", 404, "not_found")

    ok, retry = rl_hit("activate_code", hash_code(code)[:16])
    if not ok:
        sec_event("rate_limited_activate_code", "같은 코드로 활성화 요청 과다", target=hash_code(code)[:8])
        return rate_limited_response(retry)

    db = get_db()
    row = db.execute("SELECT * FROM licenses WHERE code_hash = ?", (hash_code(code),)).fetchone()
    if row is None:
        return err("존재하지 않는 라이선스 코드입니다.", 404, "not_found")

    live_status = compute_live_status(row)
    if live_status == "disabled":
        return err("비활성화된 라이선스입니다.", 403, "disabled")
    if live_status == "expired":
        return err("만료된 라이선스입니다.", 403, "expired")
    if row["device_id"] and row["device_id"] != device_id:
        sec_event("activate_other_device", "다른 장치에 등록된 라이선스 사용 시도", target=row["license_id"])
        return err("이미 다른 장치에 등록된 라이선스입니다.", 409, "device_mismatch")

    ts = now_iso()
    if row["device_id"] is None:
        activated_dt = datetime.datetime.utcnow()
        expires_dt = compute_expiry(row["license_type"], activated_dt)
        db.execute(
            """UPDATE licenses SET device_id = ?, device_first_seen = ?, activated_at = ?,
               first_activated_at = ?, expires_at = ?, last_validated_at = ?, status = 'in_use'
               WHERE license_id = ?""",
            (device_id, ts, ts, ts, expires_dt.isoformat() if expires_dt else None, ts, row["license_id"]),
        )
        audit("license_activated", target=row["license_id"], actor="client", commit=False)
        db.commit()
    else:
        db.execute("UPDATE licenses SET last_validated_at = ? WHERE license_id = ?", (ts, row["license_id"]))
        db.commit()
    row = db.execute("SELECT * FROM licenses WHERE license_id = ?", (row["license_id"],)).fetchone()

    body = {
        "status": "activated",
        "license_type": row["license_type"],
        "license_type_label": LICENSE_TYPES[row["license_type"]]["label"],
        "expires_at": row["expires_at"],
        "grace_period_days": int(get_setting("grace_period_days", DEFAULT_GRACE_PERIOD_DAYS)),
        "server_time": now_iso(),
        "app_version_seen": _clean(data.get("app_version", "unknown"), 20),
    }
    lease = make_lease(row, device_id, nonce)
    if lease:
        body["lease"] = lease
    return jsonify(body)


@app.post("/license/validate")
def validate_license():
    ip = client_ip()
    ok, retry = rl_hit("validate_ip", ip)
    if not ok:
        sec_event("rate_limited_validate_ip", "검증 요청 과다")
        return rate_limited_response(retry)

    data = json_body()
    bad, nonce = check_freshness(data)
    if bad is not None:
        return bad

    code = normalize_code(data.get("code"))
    device_id = normalize_device(data.get("device_id"))
    if not device_id:
        return err("잘못된 요청입니다.", 400, "invalid_request")
    if not code:
        return jsonify({"valid": False, "reason": "not_found"})

    ok, retry = rl_hit("validate_code", hash_code(code)[:16])
    if not ok:
        sec_event("rate_limited_validate_code", "같은 코드로 검증 요청 과다", target=hash_code(code)[:8])
        return rate_limited_response(retry)

    db = get_db()
    row = db.execute("SELECT * FROM licenses WHERE code_hash = ?", (hash_code(code),)).fetchone()
    if row is None:
        return jsonify({"valid": False, "reason": "not_found"})
    if row["device_id"] != device_id:
        return jsonify({"valid": False, "reason": "device_mismatch"})

    live_status = compute_live_status(row)
    if live_status == "disabled":
        return jsonify({"valid": False, "reason": "disabled"})
    if live_status == "expired":
        return jsonify({"valid": False, "reason": "expired"})

    db.execute("UPDATE licenses SET last_validated_at = ? WHERE license_id = ?", (now_iso(), row["license_id"]))
    db.commit()

    body = {
        "valid": True,
        "license_type": row["license_type"],
        "license_type_label": LICENSE_TYPES[row["license_type"]]["label"],
        "expires_at": row["expires_at"],
        "grace_period_days": int(get_setting("grace_period_days", DEFAULT_GRACE_PERIOD_DAYS)),
        "server_time": now_iso(),
    }
    lease = make_lease(row, device_id, nonce)
    if lease:
        body["lease"] = lease
    return jsonify(body)


# ---------------------------------------------------------------------------
# 관리자 API
# ---------------------------------------------------------------------------

@app.post("/admin/login")
def admin_login():
    data = json_body()
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str) \
            or not (1 <= len(username.strip()) <= 64) or not (1 <= len(password) <= 256):
        return err("아이디 또는 비밀번호가 올바르지 않습니다.", 401, "login_failed")
    username = username.strip()
    ip, uname = client_ip(), username.lower()

    pair_k, ip_k, user_k = f"{uname}:{ip}", ip, uname
    for kind, ident in (("login_fail_pair", pair_k), ("login_fail_ip", ip_k), ("login_fail_user", user_k)):
        window, limit = RATE[kind]
        if rl_count(f"{kind}:{ident}", window) >= limit:
            sec_event("admin_login_locked", f"user={_clean(uname, 32)}")
            retry = window
            resp = err("로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.", 429, "locked", retry_after=retry)
            resp.headers["Retry-After"] = str(retry)
            return resp

    row = get_db().execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
    # 계정이 없어도 같은 시간만큼 해시 계산을 해서 '아이디 존재 여부'가 응답 시간으로 드러나지 않게 한다.
    valid = check_password_hash(row["password_hash"] if row else DUMMY_HASH, password) and row is not None
    if not valid:
        for kind, ident in (("login_fail_pair", pair_k), ("login_fail_ip", ip_k), ("login_fail_user", user_k)):
            _rl_incr(f"{kind}:{ident}", RATE[kind][0])
        sec_event("admin_login_failed", f"user={_clean(uname, 32)}")
        time.sleep(LOGIN_FAIL_DELAY)
        return err("아이디 또는 비밀번호가 올바르지 않습니다.", 401, "login_failed")

    token, ttl = issue_admin_session(username)
    audit("admin_login", actor=username)
    return jsonify({"token": token, "expires_in": ttl})


@app.post("/admin/logout")
@require_admin
def admin_logout():
    data = json_body()
    db = get_db()
    if data.get("all") is True:
        db.execute("UPDATE admin_sessions SET revoked = 1 WHERE username = ?", (g.admin_user,))
        audit("admin_logout_all", commit=False)
    else:
        db.execute("UPDATE admin_sessions SET revoked = 1 WHERE jti = ?", (g.admin_jti,))
        audit("admin_logout", commit=False)
    db.commit()
    return jsonify({"status": "ok"})


@app.post("/admin/licenses")
@require_admin
def admin_create_license():
    data = json_body()
    license_type = data.get("license_type")
    memo = _clean(data.get("memo") or "", 200).strip()
    if license_type not in LICENSE_TYPES:
        return err("라이선스 종류가 올바르지 않습니다.", 400, "invalid_request")

    db = get_db()
    for _ in range(5):
        code = generate_license_code()
        code_hash = hash_code(code)
        if not db.execute("SELECT 1 FROM licenses WHERE code_hash = ?", (code_hash,)).fetchone():
            break
    else:
        return err("코드 생성 충돌이 반복되었습니다. 다시 시도하세요.", 500, "server_error")

    license_id = secrets.token_hex(8)
    db.execute(
        """INSERT INTO licenses (license_id, code_hash, code_display, license_type, created_at, status, memo)
           VALUES (?, ?, ?, ?, ?, 'available', ?)""",
        (license_id, code_hash, mask_code(code), license_type, now_iso(), memo),
    )
    audit("license_created", target=license_id, detail=f"type={license_type}", commit=False)
    db.commit()
    return jsonify({
        "license_id": license_id,
        "code": code,  # 평문 코드는 이 응답에서 딱 한 번만 반환된다 (DB/기록에는 저장하지 않음)
        "license_type": license_type,
        "license_type_label": LICENSE_TYPES[license_type]["label"],
        "memo": memo,
    })


@app.get("/admin/licenses")
@require_admin
def admin_list_licenses():
    status_filter = request.args.get("status")
    search = _clean(request.args.get("search") or "", 40).strip().upper()
    rows = get_db().execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
    result = []
    for row in rows:
        live_status = compute_live_status(row)
        if status_filter and status_filter != "all" and live_status != status_filter:
            continue
        if search and search not in row["code_display"]:
            continue
        result.append({
            "license_id": row["license_id"], "code_display": row["code_display"],
            "license_type": row["license_type"],
            "license_type_label": LICENSE_TYPES[row["license_type"]]["label"],
            "created_at": row["created_at"], "activated_at": row["activated_at"],
            "expires_at": row["expires_at"], "status": live_status, "device_id": row["device_id"],
            "device_first_seen": row["device_first_seen"], "last_validated_at": row["last_validated_at"],
            "memo": row["memo"] or "",
        })
    return jsonify(result)


def _get_license_or_404(license_id):
    if not isinstance(license_id, str) or not RE_LICENSE_ID.match(license_id):
        return None
    return get_db().execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()


@app.post("/admin/licenses/<license_id>/memo")
@require_admin
def admin_update_memo(license_id):
    memo = _clean(json_body().get("memo") or "", 200).strip()
    if _get_license_or_404(license_id) is None:
        return err("라이선스를 찾을 수 없습니다.", 404, "not_found")
    db = get_db()
    db.execute("UPDATE licenses SET memo = ? WHERE license_id = ?", (memo, license_id))
    db.commit()
    return jsonify({"status": "ok", "license_id": license_id, "memo": memo})


@app.post("/admin/licenses/<license_id>/revoke")
@require_admin
def admin_revoke_license(license_id):
    bad = require_reauth(json_body())
    if bad is not None:
        return bad
    if _get_license_or_404(license_id) is None:
        return err("라이선스를 찾을 수 없습니다.", 404, "not_found")
    db = get_db()
    db.execute("UPDATE licenses SET status = 'disabled' WHERE license_id = ?", (license_id,))
    audit("license_revoked", target=license_id, commit=False)
    db.commit()
    return jsonify({"status": "disabled", "license_id": license_id})


@app.post("/admin/licenses/<license_id>/reactivate")
@require_admin
def admin_reactivate_license(license_id):
    bad = require_reauth(json_body())
    if bad is not None:
        return bad
    row = _get_license_or_404(license_id)
    if row is None:
        return err("라이선스를 찾을 수 없습니다.", 404, "not_found")
    if row["status"] != "disabled":
        return err("비활성화된 라이선스가 아닙니다.", 400, "invalid_request")
    db = get_db()
    db.execute("UPDATE licenses SET status = 'available' WHERE license_id = ?", (license_id,))
    audit("license_reactivated", target=license_id, commit=False)
    db.commit()
    row = db.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
    return jsonify({"status": compute_live_status(row), "license_id": license_id})


@app.post("/admin/licenses/<license_id>/delete")
@require_admin
def admin_delete_license(license_id):
    bad = require_reauth(json_body())
    if bad is not None:
        return bad
    if _get_license_or_404(license_id) is None:
        return err("라이선스를 찾을 수 없습니다.", 404, "not_found")
    db = get_db()
    db.execute("DELETE FROM licenses WHERE license_id = ?", (license_id,))
    audit("license_deleted", target=license_id, commit=False)
    db.commit()
    return jsonify({"status": "deleted", "license_id": license_id})


@app.get("/admin/dashboard")
@require_admin
def admin_dashboard():
    rows = get_db().execute("SELECT * FROM licenses").fetchall()
    counts = {"total": len(rows), "available": 0, "in_use": 0, "expired": 0, "disabled": 0}
    for row in rows:
        s = compute_live_status(row)
        counts[s] = counts.get(s, 0) + 1
    return jsonify(counts)


@app.post("/license/deactivate-device")
@require_admin
def user_deactivate_device_alias():
    """스펙 문서에는 사용자 API로 분류되어 있으나, 보안상 관리자 인증이 필요한 기능으로 구현한다."""
    license_id = json_body().get("license_id")
    if not license_id:
        return err("license_id가 필요합니다.", 400, "invalid_request")
    return admin_reset_device(license_id)


@app.post("/admin/licenses/<license_id>/reset-device")
@require_admin
def admin_reset_device(license_id):
    """장치 등록만 해제한다. 최초 활성화 기준 만료일은 유지(기간 무한 연장 악용 방지)."""
    bad = require_reauth(json_body())
    if bad is not None:
        return bad
    row = _get_license_or_404(license_id)
    if row is None:
        return err("라이선스를 찾을 수 없습니다.", 404, "not_found")
    new_status = "disabled" if row["status"] == "disabled" else "available"
    db = get_db()
    db.execute(
        "UPDATE licenses SET device_id = NULL, device_first_seen = NULL, status = ? WHERE license_id = ?",
        (new_status, license_id),
    )
    audit("device_reset", target=license_id, commit=False)
    db.commit()
    return jsonify({"status": "device_reset", "license_id": license_id})


@app.get("/admin/settings")
@require_admin
def admin_get_settings():
    return jsonify({"grace_period_days": int(get_setting("grace_period_days", DEFAULT_GRACE_PERIOD_DAYS))})


@app.post("/admin/settings")
@require_admin
def admin_update_settings():
    data = json_body()
    if "grace_period_days" in data:
        try:
            days = int(data["grace_period_days"])
        except (TypeError, ValueError):
            return err("유예 기간은 숫자여야 합니다.", 400, "invalid_request")
        if not (0 <= days <= 90):
            return err("유예 기간은 0~90일 사이여야 합니다.", 400, "invalid_request")
        db = get_db()
        db.execute(
            "INSERT INTO settings (key, value) VALUES ('grace_period_days', ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value", (str(days),))
        audit("settings_changed", detail=f"grace_period_days={days}", commit=False)
        db.commit()
    return admin_get_settings()


@app.get("/admin/audit")
@require_admin
def admin_audit():
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 500))
    except ValueError:
        limit = 100
    category = request.args.get("category")
    sql = "SELECT * FROM audit_log"
    params = []
    if category in ("admin", "security"):
        sql += " WHERE category = ?"
        params.append(category)
    sql += " ORDER BY ts DESC, id DESC"
    rows = get_db().execute(sql, tuple(params)).fetchall()[:limit]
    return jsonify([{k: r[k] for k in AUDIT_COLS} for r in rows])


def _export_data():
    db = get_db()
    lic = [{c: r[c] for c in LICENSE_COLS} for r in db.execute("SELECT * FROM licenses").fetchall()]
    st = [{"key": r["key"], "value": r["value"]} for r in db.execute("SELECT * FROM settings").fetchall()]
    au = [{c: r[c] for c in AUDIT_COLS} for r in db.execute("SELECT * FROM audit_log").fetchall()]
    return {"format": "restime-backup-v1", "created_at": now_iso(),
            "licenses": lic, "settings": st, "audit_log": au}


@app.post("/admin/backup")
@require_admin
def admin_backup():
    """라이선스(해시 상태), 설정, 기록의 백업 JSON. 관리자 비밀번호 해시와 세션은 포함하지 않는다."""
    bad = require_reauth(json_body())
    if bad is not None:
        return bad
    audit("backup_exported")
    return jsonify(_export_data())


# ---------------------------------------------------------------------------
# 명령줄 도구 (서버 PC/배포 환경에서만 실행 - API로 노출하지 않음)
# ---------------------------------------------------------------------------

def create_admin_cli():
    import getpass

    username = input("관리자 아이디: ").strip()
    password = getpass.getpass("관리자 비밀번호: ")
    password2 = getpass.getpass("비밀번호 확인: ")
    if password != password2:
        print("비밀번호가 일치하지 않습니다.")
        return
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?) "
            "ON CONFLICT (username) DO UPDATE SET password_hash = excluded.password_hash",
            (username, generate_password_hash(password)),
        )
        conn.commit()
    finally:
        conn.close()
    print(f"관리자 계정 '{username}' 생성 완료.")


def backup_cli(path):
    conn = _connect()
    try:
        lic = [{c: r[c] for c in LICENSE_COLS} for r in conn.execute("SELECT * FROM licenses").fetchall()]
        st = [{"key": r["key"], "value": r["value"]} for r in conn.execute("SELECT * FROM settings").fetchall()]
        au = [{c: r[c] for c in AUDIT_COLS} for r in conn.execute("SELECT * FROM audit_log").fetchall()]
    finally:
        conn.close()
    data = {"format": "restime-backup-v1", "created_at": now_iso(), "licenses": lic, "settings": st, "audit_log": au}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"백업 완료: {path} (라이선스 {len(lic)}건, 기록 {len(au)}건)")


def restore_cli(path, yes=False):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("format") != "restime-backup-v1":
        raise SystemExit("지원하지 않는 백업 파일입니다.")
    if not yes:
        ans = input(f"라이선스 {len(data['licenses'])}건을 복원합니다. 같은 ID는 덮어씁니다. 계속할까요? (yes 입력): ")
        if ans.strip().lower() != "yes":
            raise SystemExit("취소했습니다.")
    conn = _connect()
    try:
        for row in data["licenses"]:
            cols = [c for c in LICENSE_COLS if c in row]
            ph = ", ".join("?" for _ in cols)
            upd = ", ".join(f"{c} = excluded.{c}" for c in cols if c != "license_id")
            conn.execute(
                f"INSERT INTO licenses ({', '.join(cols)}) VALUES ({ph}) ON CONFLICT (license_id) DO UPDATE SET {upd}",
                tuple(row[c] if row[c] is not None else None for c in cols),
            )
        for s in data.get("settings", []):
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (s["key"], s["value"]),
            )
        for a in data.get("audit_log", []):
            cols = [c for c in AUDIT_COLS if c in a]
            conn.execute(
                f"INSERT INTO audit_log ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)}) ON CONFLICT (id) DO NOTHING",
                tuple(a[c] for c in cols),
            )
        conn.commit()
    finally:
        conn.close()
    print(f"복원 완료: 라이선스 {len(data['licenses'])}건")


if __name__ == "__main__":
    import sys

    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "create-admin":
        create_admin_cli()
    elif cmd == "backup" and len(sys.argv) > 2:
        backup_cli(sys.argv[2])
    elif cmd == "restore" and len(sys.argv) > 2:
        restore_cli(sys.argv[2], yes=("--yes" in sys.argv))
    else:
        port = int(os.environ.get("PORT", 5000))
        app.run(host="0.0.0.0", port=port, debug=False)
