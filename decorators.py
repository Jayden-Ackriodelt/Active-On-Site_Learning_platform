from functools import wraps
from flask import request, jsonify
import jwt
import os

SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key")

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"message": "Login ဝင်ရန် (Token) လိုအပ်ပါသည်"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token သက်တမ်းကုန်ပါပြီ"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token မမှန်ကန်ပါ"}), 401

        if payload.get("role") != "admin":
            return jsonify({"message": "Admin ခွင့်ပြုချက် မရှိပါ"}), 403

        request.current_user = payload
        return f(*args, **kwargs)

    return decorated