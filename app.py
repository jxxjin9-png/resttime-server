# -*- coding: utf-8 -*-
"""
RestTime License Server
========================
사용자 프로그램(RestTime.exe)과 관리자 프로그램(RestTime Admin.exe)이
공통으로 통신하는 라이선스 발급/검증 서버.

- 사용자 API: /license/*        (device 기반, 인증 없음 - 코드 자체가 비밀)
- 관리자 API: /admin/*          (JWT 로그인 필요)

실행:
    pip install -r requirements.txt
    python app.py

배포 시 반드시 HTTPS 리버스 프록시(nginx + certbot 등) 뒤에 두세요.
이 서버 자체는 평문 HTTP로 동작하므로 개발용입니다.
"""

import os
import sqlite3
import secrets
import hashlib
import datetime
import functools

from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from dateutil.relativedelta import relativedelta
import jwt

# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "license.db")

# JWT 서명 비밀키: 반드시 환경변수로 주입한다. 코드에 하드코딩하지 않는다.
JWT_SECRET = os.environ.get("RESTTIME_JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError(
        "환경변수 RESTTIME_JWT_SECRET 이 설정되지 않았습니다.\n"
        "예: export RESTTIME_JWT_SECRET=$(python -c \"import secrets;print(secrets.token_hex(32))\")"
    )

JWT_EXPIRE_HOURS = 8

# 오프라인 유예 기간(일) - 마지막 정상 인증 이후 이 기간 동안은
# 서버 연결이 끊겨도 클라이언트가 로컬 캐시로 계속 동작할 수 있게 허용.
# 관리자가 /admin/settings 로 조정 가능하도록 DB의 settings 테이블에 저장한다.
DEFAULT_GRACE_PERIOD_DAYS = 3

LICENSE_TYPES = {
    "1day": {"label": "1 Day", "delta": lambda: relativedelta(days=1)},
    "7day": {"label": "7 Days", "delta": lambda: relativedelta(days=7)},
    "1month": {"label": "1 Month", "delta": lambda: relativedelta(months=1)},
    "1year": {"label": "1 Year", "delta": lambda: relativedelta(years=1)},
    "lifetime": {"label": "Lifetime", "delta": None},
}

app = Flask(__name__)


# ---------------------------------------------------------------------------
# DB 헬퍼
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS licenses (
            license_id          TEXT PRIMARY KEY,
            code_hash            TEXT UNIQUE NOT NULL,
            code_display          TEXT NOT NULL,   -- 마스킹된 코드 (목록 표시용)
            license_type          TEXT NOT NULL,
            created_at            TEXT NOT NULL,
            activated_at          TEXT,
            first_activated_at    TEXT,
            expires_at            TEXT,
            status                TEXT NOT NULL DEFAULT 'available',
                                    -- available / in_use / expired / disabled
            device_id             TEXT,
            device_first_seen     TEXT,
            last_validated_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS admins (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
        ("grace_period_days", str(DEFAULT_GRACE_PERIOD_DAYS)),
    )
    conn.commit()

    # 쉘 접근이 없는 호스팅 서비스(Render 등)에서도 관리자 계정을 만들 수 있도록,
    # 환경변수로 ADMIN_USERNAME / ADMIN_PASSWORD가 설정되어 있으면
    # 서버 시작 시 자동으로 (없을 때만) 관리자 계정을 만든다.
    # INSERT OR IGNORE를 사용해 원자적으로 처리한다 - SELECT 후 INSERT하는 방식은
    # 여러 워커 프로세스가 동시에 뜰 때(gunicorn -w 2 등) 경쟁 상태로 인해
    # UNIQUE 제약 위반이 발생해 서버 부팅이 실패할 수 있다.
    seed_user = os.environ.get("ADMIN_USERNAME")
    seed_pass = os.environ.get("ADMIN_PASSWORD")
    if seed_user and seed_pass:
        conn.execute(
            "INSERT OR IGNORE INTO admins (username, password_hash) VALUES (?, ?)",
            (seed_user, generate_password_hash(seed_pass)),
        )
        conn.commit()
    conn.close()


def get_setting(key, default=None):
    row = get_db().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


# 모듈이 임포트되는 순간 항상 실행된다.
# `python app.py`로 직접 실행할 때뿐 아니라, 운영 배포에서 쓰는
# `gunicorn app:app` 처럼 모듈만 import되는 경우에도 DB 테이블 생성과
# 관리자 계정 자동 시드(ADMIN_USERNAME/ADMIN_PASSWORD)가 반드시 실행되어야
# 하기 때문에, __main__ 블록이 아니라 여기서 호출한다.
init_db()


# ---------------------------------------------------------------------------
# 유틸
# ---------------------------------------------------------------------------

def now_iso():
    return datetime.datetime.utcnow().isoformat()


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def generate_license_code() -> str:
    """RTM7-X4KD-92PQ-L8NF 형태의 추측 불가능한 코드 생성."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 혼동되는 0/O, 1/I 제외
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
        return None  # lifetime
    return from_time + delta_fn()


def row_to_dict(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in row.keys()}


def compute_live_status(row: sqlite3.Row) -> str:
    """DB에 저장된 status에 만료 여부를 실시간 반영."""
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


# ---------------------------------------------------------------------------
# 관리자 인증
# ---------------------------------------------------------------------------

def issue_jwt(username: str) -> str:
    payload = {
        "sub": username,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def require_admin(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "인증 토큰이 필요합니다."}), 401
        token = auth.split(" ", 1)[1]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "토큰이 만료되었습니다. 다시 로그인하세요."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "유효하지 않은 토큰입니다."}), 401
        return fn(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# 사용자 API
# ---------------------------------------------------------------------------

@app.post("/license/activate")
def activate_license():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip().upper()
    device_id = (data.get("device_id") or "").strip()
    app_version = data.get("app_version", "unknown")

    if not code or not device_id:
        return jsonify({"error": "code와 device_id는 필수입니다."}), 400

    db = get_db()
    row = db.execute(
        "SELECT * FROM licenses WHERE code_hash = ?", (hash_code(code),)
    ).fetchone()

    if row is None:
        return jsonify({"error": "존재하지 않는 라이선스 코드입니다."}), 404

    live_status = compute_live_status(row)

    if live_status == "disabled":
        return jsonify({"error": "비활성화된 라이선스입니다."}), 403
    if live_status == "expired":
        return jsonify({"error": "만료된 라이선스입니다."}), 403

    if row["device_id"] and row["device_id"] != device_id:
        return jsonify({"error": "이미 다른 장치에 등록된 라이선스입니다."}), 409

    ts = now_iso()

    if row["device_id"] is None:
        # 최초 활성화: 여기서부터 기간 계산 시작
        activated_dt = datetime.datetime.utcnow()
        expires_dt = compute_expiry(row["license_type"], activated_dt)
        db.execute(
            """UPDATE licenses
               SET device_id = ?, device_first_seen = ?,
                   activated_at = ?, first_activated_at = ?,
                   expires_at = ?, last_validated_at = ?, status = 'in_use'
               WHERE license_id = ?""",
            (
                device_id, ts, ts, ts,
                expires_dt.isoformat() if expires_dt else None,
                ts, row["license_id"],
            ),
        )
        db.commit()
        expires_at = expires_dt.isoformat() if expires_dt else None
    else:
        # 같은 장치 재등록(재설치 등) - 만료일은 최초 등록 시점 기준 유지
        db.execute(
            "UPDATE licenses SET last_validated_at = ? WHERE license_id = ?",
            (ts, row["license_id"]),
        )
        db.commit()
        expires_at = row["expires_at"]

    return jsonify(
        {
            "status": "activated",
            "license_type": row["license_type"],
            "license_type_label": LICENSE_TYPES[row["license_type"]]["label"],
            "expires_at": expires_at,
            "grace_period_days": int(get_setting("grace_period_days", DEFAULT_GRACE_PERIOD_DAYS)),
            "app_version_seen": app_version,
        }
    )


@app.post("/license/validate")
def validate_license():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip().upper()
    device_id = (data.get("device_id") or "").strip()

    if not code or not device_id:
        return jsonify({"error": "code와 device_id는 필수입니다."}), 400

    db = get_db()
    row = db.execute(
        "SELECT * FROM licenses WHERE code_hash = ?", (hash_code(code),)
    ).fetchone()

    if row is None:
        return jsonify({"valid": False, "reason": "not_found"})

    if row["device_id"] != device_id:
        return jsonify({"valid": False, "reason": "device_mismatch"})

    live_status = compute_live_status(row)
    if live_status == "disabled":
        return jsonify({"valid": False, "reason": "disabled"})
    if live_status == "expired":
        return jsonify({"valid": False, "reason": "expired"})

    db.execute(
        "UPDATE licenses SET last_validated_at = ? WHERE license_id = ?",
        (now_iso(), row["license_id"]),
    )
    db.commit()

    return jsonify(
        {
            "valid": True,
            "license_type": row["license_type"],
            "license_type_label": LICENSE_TYPES[row["license_type"]]["label"],
            "expires_at": row["expires_at"],
            "grace_period_days": int(get_setting("grace_period_days", DEFAULT_GRACE_PERIOD_DAYS)),
            "server_time": now_iso(),
        }
    )


# ---------------------------------------------------------------------------
# 관리자 API
# ---------------------------------------------------------------------------

@app.post("/admin/login")
def admin_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = get_db()
    row = db.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "아이디 또는 비밀번호가 올바르지 않습니다."}), 401

    return jsonify({"token": issue_jwt(username)})


@app.post("/admin/licenses")
@require_admin
def admin_create_license():
    data = request.get_json(silent=True) or {}
    license_type = data.get("license_type")
    if license_type not in LICENSE_TYPES:
        return jsonify({"error": f"license_type은 {list(LICENSE_TYPES)} 중 하나여야 합니다."}), 400

    db = get_db()
    for _ in range(5):
        code = generate_license_code()
        code_hash = hash_code(code)
        exists = db.execute(
            "SELECT 1 FROM licenses WHERE code_hash = ?", (code_hash,)
        ).fetchone()
        if not exists:
            break
    else:
        return jsonify({"error": "코드 생성 충돌이 반복되었습니다. 다시 시도하세요."}), 500

    license_id = secrets.token_hex(8)
    db.execute(
        """INSERT INTO licenses
           (license_id, code_hash, code_display, license_type, created_at, status)
           VALUES (?, ?, ?, ?, ?, 'available')""",
        (license_id, code_hash, mask_code(code), license_type, now_iso()),
    )
    db.commit()

    return jsonify(
        {
            "license_id": license_id,
            "code": code,  # 평문 코드는 이 응답에서 딱 한 번만 반환된다
            "license_type": license_type,
            "license_type_label": LICENSE_TYPES[license_type]["label"],
        }
    )


@app.get("/admin/licenses")
@require_admin
def admin_list_licenses():
    status_filter = request.args.get("status")  # available/in_use/expired/disabled
    search = (request.args.get("search") or "").strip().upper()
    db = get_db()
    rows = db.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()

    result = []
    for row in rows:
        live_status = compute_live_status(row)
        if status_filter and status_filter != "all" and live_status != status_filter:
            continue
        if search and search not in row["code_display"]:
            continue
        result.append(
            {
                "license_id": row["license_id"],
                "code_display": row["code_display"],
                "license_type": row["license_type"],
                "license_type_label": LICENSE_TYPES[row["license_type"]]["label"],
                "created_at": row["created_at"],
                "activated_at": row["activated_at"],
                "expires_at": row["expires_at"],
                "status": live_status,
                "device_id": row["device_id"],
                "device_first_seen": row["device_first_seen"],
                "last_validated_at": row["last_validated_at"],
            }
        )
    return jsonify(result)


@app.post("/admin/licenses/<license_id>/revoke")
@require_admin
def admin_revoke_license(license_id):
    db = get_db()
    row = db.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
    if row is None:
        return jsonify({"error": "라이선스를 찾을 수 없습니다."}), 404

    db.execute(
        "UPDATE licenses SET status = 'disabled' WHERE license_id = ?", (license_id,)
    )
    db.commit()
    return jsonify({"status": "disabled", "license_id": license_id})


@app.post("/admin/licenses/<license_id>/reactivate")
@require_admin
def admin_reactivate_license(license_id):
    """비활성화를 취소한다. 장치 등록/만료일은 그대로 유지되므로,
    이전에 어떤 장치에 등록되어 있었다면 그 상태(사용 중) 그대로 복원되고,
    이미 만료된 라이선스라면 만료 상태로 표시된다."""
    db = get_db()
    row = db.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
    if row is None:
        return jsonify({"error": "라이선스를 찾을 수 없습니다."}), 404
    if row["status"] != "disabled":
        return jsonify({"error": "비활성화된 라이선스가 아닙니다."}), 400

    db.execute(
        "UPDATE licenses SET status = 'available' WHERE license_id = ?", (license_id,)
    )
    db.commit()
    row = db.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
    return jsonify({"status": compute_live_status(row), "license_id": license_id})


@app.post("/admin/licenses/<license_id>/delete")
@require_admin
def admin_delete_license(license_id):
    """라이선스를 데이터베이스에서 완전히 삭제한다 (되돌릴 수 없음)."""
    db = get_db()
    row = db.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
    if row is None:
        return jsonify({"error": "라이선스를 찾을 수 없습니다."}), 404
    db.execute("DELETE FROM licenses WHERE license_id = ?", (license_id,))
    db.commit()
    return jsonify({"status": "deleted", "license_id": license_id})


@app.get("/admin/dashboard")
@require_admin
def admin_dashboard():
    db = get_db()
    rows = db.execute("SELECT * FROM licenses").fetchall()
    counts = {"total": len(rows), "available": 0, "in_use": 0, "expired": 0, "disabled": 0}
    for row in rows:
        live_status = compute_live_status(row)
        counts[live_status] = counts.get(live_status, 0) + 1
    return jsonify(counts)


@app.post("/license/deactivate-device")
@require_admin
def user_deactivate_device_alias():
    """스펙 문서에는 사용자 API로 분류되어 있으나, 보안상 장치 등록 해제는
    관리자 인증이 필요한 기능으로 구현한다 (일반 사용자 프로그램에는 이 기능을
    노출하지 않음). admin_reset_device와 동일 동작을 license_id로 수행한다."""
    data = request.get_json(silent=True) or {}
    license_id = data.get("license_id")
    if not license_id:
        return jsonify({"error": "license_id가 필요합니다."}), 400
    return admin_reset_device(license_id)


@app.post("/admin/licenses/<license_id>/reset-device")
@require_admin
def admin_reset_device(license_id):
    """장치 등록만 해제한다. 최초 활성화 시점 기준 만료일은 유지한다
    (기간을 무한정 늘리는 악용을 막기 위함)."""
    db = get_db()
    row = db.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
    if row is None:
        return jsonify({"error": "라이선스를 찾을 수 없습니다."}), 404

    new_status = "disabled" if row["status"] == "disabled" else "available"
    db.execute(
        """UPDATE licenses
           SET device_id = NULL, device_first_seen = NULL, status = ?
           WHERE license_id = ?""",
        (new_status, license_id),
    )
    db.commit()
    return jsonify({"status": "device_reset", "license_id": license_id})


@app.get("/admin/settings")
@require_admin
def admin_get_settings():
    return jsonify({"grace_period_days": int(get_setting("grace_period_days", DEFAULT_GRACE_PERIOD_DAYS))})


@app.post("/admin/settings")
@require_admin
def admin_update_settings():
    data = request.get_json(silent=True) or {}
    if "grace_period_days" in data:
        db = get_db()
        db.execute(
            "INSERT INTO settings (key, value) VALUES ('grace_period_days', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(int(data["grace_period_days"])),),
        )
        db.commit()
    return admin_get_settings()


# ---------------------------------------------------------------------------
# 관리자 계정 생성 (최초 1회, CLI로만 실행 - API로 노출하지 않음)
# ---------------------------------------------------------------------------

def create_admin_cli():
    import getpass

    init_db()
    username = input("관리자 아이디: ").strip()
    password = getpass.getpass("관리자 비밀번호: ")
    password2 = getpass.getpass("비밀번호 확인: ")
    if password != password2:
        print("비밀번호가 일치하지 않습니다.")
        return
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO admins (username, password_hash) VALUES (?, ?)",
        (username, generate_password_hash(password)),
    )
    conn.commit()
    conn.close()
    print(f"관리자 계정 '{username}' 생성 완료.")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        create_admin_cli()
    else:
        # Render/Railway 등 대부분의 호스팅 플랫폼은 PORT 환경변수로
        # 실제 포트를 지정해준다. 없으면 로컬 개발용 5000번 사용.
        port = int(os.environ.get("PORT", 5000))
        app.run(host="0.0.0.0", port=port, debug=False)
