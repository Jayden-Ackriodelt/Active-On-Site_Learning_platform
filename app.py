import datetime
import json
import os
import random
import time
import urllib.error
import urllib.request

from decorators import SECRET_KEY, admin_required
from flask import Flask, jsonify, render_template, request, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import jwt
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = SECRET_KEY
CORS(app, supports_credentials=True)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    nickname = db.Column(db.String(100), default="")
    official_name = db.Column(db.String(120), default="")
    role = db.Column(db.String(20), default="user")
    enrolled_courses = db.Column(db.Text, default="[]")


class Payment(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    user_name = db.Column(db.String(120), nullable=False)
    official_name = db.Column(db.String(120), default="")
    course_id = db.Column(db.String(80), nullable=False)
    course_title = db.Column(db.String(150), nullable=False)
    method = db.Column(db.String(60), nullable=False)
    ref = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(30), default="Pending")


class CourseProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    course_id = db.Column(db.String(80), nullable=False)
    progress_json = db.Column(
        db.Text, default='{"passedModules":[],"attempts":{}}'
    )


with app.app_context():
    db.create_all()


def send_signup_verification_email(to_email: str, code: str) -> bool:
    api_key = (os.environ.get("BREVO_API_KEY") or "").strip()
    sender_email = (
        os.environ.get("MAIL_FROM_EMAIL") or "kyawzinlatt.esl.edu@gmail.com"
    ).strip()
    sender_name = (os.environ.get("MAIL_FROM_NAME") or "AOLP").strip()

    if not api_key:
        app.logger.error("BREVO_API_KEY is missing in environment variables.")
        return False

    payload = {
        "sender": {"name": sender_name, "email": sender_email},
        "to": [{"email": to_email}],
        "subject": "AOLP Sign Up Verification Code",
        "htmlContent": (
            "<p>Welcome to AOLP Learning Platform!</p>"
            "<p>Your 6-digit sign up verification code is:"
            f" <strong>{code}</strong></p>"
            "<p>This code will expire in 5 minutes.</p>"
            "<p>Please enter this code to verify your email and create your"
            " password.</p>"
        ),
    }

    req = urllib.request.Request(
        url="https://api.brevo.com/v3/smtp/email",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "accept": "application/json",
            "api-key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "AOLP-Learning-Platform/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        app.logger.error(f"Brevo HTTP error {e.code}: {err_body}")
        return False
    except Exception as e:
        app.logger.error(f"Failed to send verification email via Brevo: {e}")
        return False


def _create_jwt_token(user_id: int, email: str, role: str) -> str:
    return jwt.encode(
        {
            "user_id": user_id,
            "email": email,
            "role": role,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        },
        SECRET_KEY,
        algorithm="HS256",
    )


def _verify_stored_password(stored_password: str, provided_password: str) -> bool:
    if not stored_password:
        return False
    try:
        if check_password_hash(stored_password, provided_password):
            return True
    except ValueError:
        pass
    return stored_password == provided_password


@app.route("/")
def home():
    return render_template("AOLP_ADMIN_MASTER_ACCESS.html")


# Step 1: Name + Email ထည့်ပြီး 6-digit code ကို Email သို့ ပို့ခြင်း
@app.route("/api/signup/send-code", methods=["POST"])
def signup_send_code():
    data = request.get_json(silent=True) or {}
    nickname = (data.get("nickname") or data.get("name") or "").strip()
    official_name = (
        data.get("official_name") or data.get("officialName") or nickname
    ).strip()
    email = (data.get("email") or "").strip().lower()

    if not nickname or not official_name or not email or "@" not in email:
        return (
            jsonify({"message": "Please provide valid name and email address."}),
            400,
        )

    if email == "kyawzinlatt.esl.edu@gmail.com":
        return (
            jsonify({"message": "This email is reserved for administrator."}),
            400,
        )

    if User.query.filter_by(email=email).first():
        return (
            jsonify({
                "message": (
                    "This email is already registered. Please sign in instead."
                )
            }),
            409,
        )

    code = f"{random.randint(0, 999999):06d}"
    session["pending_signup"] = {
        "nickname": nickname,
        "official_name": official_name,
        "email": email,
        "code": code,
        "expires_at": time.time() + 300,  # 5 minutes
        "verified": False,
    }

    sent = send_signup_verification_email(email, code)
    if not sent:
        session.pop("pending_signup", None)
        return (
            jsonify({
                "message": (
                    "Unable to send verification email. Check BREVO_API_KEY,"
                    " MAIL_FROM_EMAIL, and MAIL_FROM_NAME in Render."
                )
            }),
            500,
        )

    return jsonify({
        "message": f"A 6-digit verification code has been sent to {email}."
    }), 200


# Step 2: 6-digit code မှန်မမှန် စစ်ဆေးခြင်း (မှန်မှ password ပြုလုပ်ခွင့် ပေးမည်)
@app.route("/api/signup/verify-code", methods=["POST"])
def signup_verify_code():
    data = request.get_json(silent=True) or {}
    entered_code = (data.get("code") or data.get("otp") or "").strip()
    pending = session.get("pending_signup")

    if not pending:
        return (
            jsonify({
                "message": (
                    "No pending sign up session found. Please request a new code."
                )
            }),
            400,
        )

    if time.time() > pending.get("expires_at", 0):
        session.pop("pending_signup", None)
        return (
            jsonify({
                "message": (
                    "Verification code has expired. Please request a new code."
                )
            }),
            400,
        )

    if not entered_code or entered_code != pending.get("code"):
        return (
            jsonify({"message": "Invalid 6-digit verification code."}),
            400,
        )

    pending["verified"] = True
    session["pending_signup"] = pending
    return jsonify({
        "verified": True,
        "message": "Email verified! You can now create your password.",
    }), 200


# Step 3: Code အတည်ပြုပြီးမှ Password ပြုလုပ်ပြီး Account ဖန်တီးခြင်း
@app.route("/api/signup/complete", methods=["POST"])
def signup_complete():
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    pending = session.get("pending_signup")

    if not pending or not pending.get("verified"):
        return (
            jsonify({
                "message": (
                    "Please verify your 6-digit email code before creating a"
                    " password."
                )
            }),
            403,
        )

    if len(password) < 6:
        return (
            jsonify({"message": "Password must be at least 6 characters long."}),
            400,
        )

    email = pending["email"]
    if User.query.filter_by(email=email).first():
        session.pop("pending_signup", None)
        return jsonify({"message": "This email is already registered."}), 409

    new_user = User(
        email=email,
        password=generate_password_hash(password),
        nickname=pending["nickname"],
        official_name=pending["official_name"],
        role="user",
        enrolled_courses=json.dumps([]),
    )
    db.session.add(new_user)
    db.session.commit()

    session.pop("pending_signup", None)

    token = _create_jwt_token(new_user.id, new_user.email, new_user.role)
    return jsonify({
        "message": "Account created successfully.",
        "token": token,
        "role": new_user.role,
        "email": new_user.email,
        "nickname": new_user.nickname,
        "officialName": new_user.official_name,
    }), 201

@app.route("/api/forgot-password/send-code", methods=["POST"])
def forgot_password_send_code():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email or "@" not in email:
        return jsonify({"message": "Please enter a valid email address."}), 400

    if email == "kyawzinlatt.esl.edu@gmail.com":
        return jsonify({"message": "Administrator password cannot be reset from here."}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "No account found with this email address."}), 404

    code = f"{random.randint(0, 999999):06d}"
    session["pending_reset"] = {
        "email": email,
        "code": code,
        "expires_at": time.time() + 300,  # 5 minutes
        "verified": False,
    }

    sent = send_signup_verification_email(email, code)
    if not sent:
        session.pop("pending_reset", None)
        return jsonify({"message": "Unable to send reset code email. Please try again."}), 500

    return jsonify({"message": f"A 6-digit password reset code was sent to {email}."}), 200


@app.route("/api/forgot-password/verify-code", methods=["POST"])
def forgot_password_verify_code():
    data = request.get_json(silent=True) or {}
    entered_code = (data.get("code") or data.get("otp") or "").strip()
    pending = session.get("pending_reset")

    if not pending:
        return jsonify({"message": "No password reset request found. Please request a new code."}), 400

    if time.time() > pending.get("expires_at", 0):
        session.pop("pending_reset", None)
        return jsonify({"message": "Reset code has expired. Please request a new code."}), 400

    if not entered_code or entered_code != pending.get("code"):
        return jsonify({"message": "Invalid 6-digit reset code."}), 400

    pending["verified"] = True
    session["pending_reset"] = pending
    return jsonify({"verified": True, "message": "Code verified! Set new password."}), 200


@app.route("/api/forgot-password/reset", methods=["POST"])
def forgot_password_reset():
    data = request.get_json(silent=True) or {}
    new_password = data.get("password") or ""
    pending = session.get("pending_reset")

    if not pending or not pending.get("verified"):
        return jsonify({"message": "Please verify the reset code first."}), 403

    if len(new_password) < 6:
        return jsonify({"message": "Password must be at least 6 characters long."}), 400

    user = User.query.filter_by(email=pending["email"]).first()
    if not user:
        session.pop("pending_reset", None)
        return jsonify({"message": "User account not found."}), 404

    user.password = generate_password_hash(new_password)
    db.session.commit()
    session.pop("pending_reset", None)

    return jsonify({
        "message": "Password updated successfully. You can now log in with your new password."
    }), 200

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    if email == "kyawzinlatt.esl.edu@gmail.com":
        if password != "@AdminLogin15219#":
            return jsonify({"message": "Invalid administrator credentials"}), 401
        admin_user = User.query.filter_by(email=email).first()
        if not admin_user:
            admin_user = User(
                email=email,
                password=generate_password_hash(password),
                nickname="Admin",
                official_name="Kyaw Zin Latt",
                role="admin",
                enrolled_courses=json.dumps([]),
            )
            db.session.add(admin_user)
            db.session.commit()
        user_id = admin_user.id
        role = "admin"
        nickname = admin_user.nickname or "Admin"
        official_name = admin_user.official_name or "Kyaw Zin Latt"
    else:
        user = User.query.filter_by(email=email).first()
        if not user or not _verify_stored_password(user.password, password):
            return jsonify({"message": "Invalid email or password"}), 401
        user_id = user.id
        role = user.role or "user"
        nickname = user.nickname or email.split("@")[0]
        official_name = user.official_name or nickname

    token = _create_jwt_token(user_id, email, role)
    return jsonify({
        "token": token,
        "role": role,
        "email": email,
        "nickname": nickname,
        "officialName": official_name,
    }), 200


@app.route("/api/admin/delete-user/<int:target_user_id>", methods=["DELETE"])
@admin_required
def delete_user(target_user_id):
    return jsonify({
        "message": (
            f"User ID {target_user_id} ကို Admin"
            f" ({request.current_user['user_id']}) က ဖျက်လိုက်ပါပြီ"
        )
    }), 200


@app.route("/api/admin/approve-payment", methods=["POST"])
@admin_required
def api_approve_payment():
    data = request.get_json(silent=True) or {}
    payment_id = (data.get("paymentId") or "").strip()
    payment = Payment.query.filter_by(id=payment_id).first()

    if not payment:
        return jsonify({"message": "Payment record not found"}), 404

    payment.status = "Approved"

    target_user = User.query.filter_by(
        email=payment.user_email.lower()
    ).first()
    if target_user:
        try:
            enrolled = json.loads(target_user.enrolled_courses or "[]")
        except ValueError:
            enrolled = []
        if payment.course_id not in enrolled:
            enrolled.append(payment.course_id)
        target_user.enrolled_courses = json.dumps(enrolled)

    db.session.commit()
    return jsonify({
        "message": f"Server approved payment {payment_id}",
        "paymentId": payment_id,
        "status": "Approved",
    }), 200


@app.route("/api/admin/deny-payment", methods=["POST"])
@admin_required
def api_deny_payment():
    data = request.get_json(silent=True) or {}
    payment_id = (data.get("paymentId") or "").strip()
    payment = Payment.query.filter_by(id=payment_id).first()

    if not payment:
        return jsonify({"message": "Payment record not found"}), 404

    payment.status = "Denied"
    db.session.commit()
    return jsonify({
        "message": f"Server denied payment {payment_id}",
        "paymentId": payment_id,
        "status": "Denied",
    }), 200


def _decode_token_from_header():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


@app.route("/api/payments", methods=["GET", "POST"])
def api_payments():
    payload = _decode_token_from_header()
    if not payload:
        return jsonify({"message": "Unauthorized"}), 401

    user_email = (payload.get("email") or "").strip().lower()
    role = payload.get("role") or "user"

    if request.method == "GET":
        if role == "admin":
            rows = Payment.query.all()
        else:
            rows = Payment.query.filter_by(user_email=user_email).all()

        return jsonify({
            "payments": [
                {
                    "id": p.id,
                    "userEmail": p.user_email,
                    "userName": p.user_name,
                    "officialName": p.official_name,
                    "courseId": p.course_id,
                    "courseTitle": p.course_title,
                    "method": p.method,
                    "ref": p.ref,
                    "status": p.status,
                }
                for p in rows
            ]
        }), 200

    data = request.get_json(silent=True) or {}
    payment_id = (data.get("id") or "").strip()
    course_id = (data.get("courseId") or "").strip()
    course_title = (data.get("courseTitle") or "").strip()
    method = (data.get("method") or "").strip()
    ref = (data.get("ref") or "").strip()

    if not payment_id or not course_id or not ref:
        return jsonify({"message": "Missing payment details"}), 400

    new_payment = Payment(
        id=payment_id,
        user_email=user_email,
        user_name=(data.get("userName") or user_email.split("@")[0]).strip(),
        official_name=(data.get("officialName") or "").strip(),
        course_id=course_id,
        course_title=course_title or course_id,
        method=method or "Manual",
        ref=ref,
        status="Pending",
    )
    db.session.add(new_payment)
    db.session.commit()

    return jsonify({
        "message": "Payment submitted",
        "payment": {
            "id": new_payment.id,
            "userEmail": new_payment.user_email,
            "userName": new_payment.user_name,
            "officialName": new_payment.official_name,
            "courseId": new_payment.course_id,
            "courseTitle": new_payment.course_title,
            "method": new_payment.method,
            "ref": new_payment.ref,
            "status": new_payment.status,
        },
    }), 201


@app.route("/api/progress/<course_id>", methods=["GET", "POST"])
def api_course_progress(course_id):
    payload = _decode_token_from_header()
    if not payload:
        return jsonify({"message": "Unauthorized"}), 401

    user_email = (payload.get("email") or "").strip().lower()
    row = CourseProgress.query.filter_by(
        user_email=user_email, course_id=course_id
    ).first()

    if request.method == "GET":
        if not row:
            return jsonify(
                {"progress": {"passedModules": [], "attempts": {}}}
            ), 200
        try:
            parsed = json.loads(row.progress_json or "{}")
        except ValueError:
            parsed = {"passedModules": [], "attempts": {}}
        return jsonify({
            "progress": {
                "passedModules": parsed.get("passedModules", []),
                "attempts": parsed.get("attempts", {}),
            }
        }), 200

    data = request.get_json(silent=True) or {}
    clean_progress = {
        "passedModules": data.get("passedModules", []),
        "attempts": data.get("attempts", {}),
    }
    if not row:
        row = CourseProgress(
            user_email=user_email,
            course_id=course_id,
            progress_json=json.dumps(clean_progress),
        )
        db.session.add(row)
    else:
        row.progress_json = json.dumps(clean_progress)

    db.session.commit()
    return jsonify(
        {"message": "Progress saved", "progress": clean_progress}
    ), 200


if __name__ == "__main__":
    app.run(debug=True)