import os
import time
import jwt
from flask import Flask, request, send_from_directory, jsonify, abort

app = Flask(__name__)

# Ortam değişkenlerini al
JWT_SECRET = os.environ.get("JWT_SECRET", "supersecret")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "adminkey")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
ALLOWED_USERS = []  # boş → herkes erişebilir
ALLOW_SINGLE_USE = os.environ.get("ALLOW_SINGLE_USE", "true").lower() == "true"
VERSION = os.environ.get("VERSION", "1.0.0")

# Tek kullanımlık tokenları takip etmek için hafızada dict
used_tokens = set()

FILES_DIR = "files"

@app.route("/")
def index():
    return f"Timed Download API v{VERSION}"

# Admin link oluşturma
@app.route("/create_link", methods=["POST"])
def create_link():
    api_key = request.headers.get("X-API-Key")
    if api_key != ADMIN_API_KEY:
        return {"error": "Unauthorized"}, 401

    data = request.get_json()
    filename = data.get("filename")
    expires_in = data.get("expires_in", 600)  # default 10 dakika

    if not filename or not os.path.exists(os.path.join(FILES_DIR, filename)):
        return {"error": "Dosya bulunamadı"}, 404

    payload = {
        "filename": filename,
        "exp": int(time.time()) + expires_in
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    link = f"{BASE_URL}/download?token={token}"
    return {"link": link, "version": VERSION}

# Dosya indirme
@app.route("/download")
def download():
    token = request.args.get("token")
    if not token:
        return {"error": "Token gerekli"}, 400

    if ALLOW_SINGLE_USE and token in used_tokens:
        return {"error": "Token zaten kullanıldı"}, 403

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        filename = payload["filename"]
    except jwt.ExpiredSignatureError:
        return {"error": "Token süresi dolmuş"}, 403
    except Exception:
        return {"error": "Geçersiz token"}, 403

    file_path = os.path.join(FILES_DIR, filename)
    if not os.path.exists(file_path):
        return {"error": "Dosya bulunamadı"}, 404

    if ALLOW_SINGLE_USE:
        used_tokens.add(token)

    return send_from_directory(FILES_DIR, filename, as_attachment=True)

# Sürüm bilgisi endpoint
@app.route("/version", methods=["GET"])
def get_version():
    return {"version": VERSION}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
