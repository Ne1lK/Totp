from flask import Flask, jsonify, send_from_directory, render_template_string, request
import pyotp
import qrcode
import time
import io
import base64
import os

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

secret = pyotp.random_base32()
totp = pyotp.TOTP(secret)
uri = totp.provisioning_uri(name='test', issuer_name='totp')

print("Secret for this run:", secret)
print("URI:", uri)

buf = io.BytesIO()
qrcode.make(uri).save(buf, format="PNG")
qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')


def load_html():
    with open(os.path.join(BASE_DIR, "index.html"), "r") as f:
        return f.read()

@app.route("/")
def index():
    html = load_html()
    return render_template_string(html, qr_base64=qr_base64)

@app.route("/styles.css")
def css():
    return send_from_directory(BASE_DIR, "styles.css")

@app.route("/current")
def current():
    code = totp.now()
    time_left = totp.interval - (int(time.time()) % totp.interval)
    return jsonify({"code": code, "time_left": time_left})

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    code = data.get("code")

    if not code:
        return jsonify({"ok": False, "valid": False, "error": "code is required"}), 400

    valid = bool(totp.verify(str(code)))
    return jsonify({"ok": True, "valid": valid})

if __name__ == "__main__":
    app.run(port=5050, debug=True)
