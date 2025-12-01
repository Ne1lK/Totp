# Totp
Provides OTP service for use, can be integrated to login or another service by connecting secret URI to your 2FA page, this could also be used to create your own 2fa authenticator.
also if using 2fa for login microservice, _pl.sql file will need to have power level added because this is method for determining if otp code is needed, can be changed.

if using for 2fa and bloom, replace index.js in login with example.js and rename example.js index.js
add register.handlebars to views
powerlevel will determine 2fa enabled or disabled, didn't want to modify tables
add power level to pl.sql

Response 

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    code = data.get("code")

    if not code:
        return jsonify({"ok": False, "valid": False, "error": "code is required"}), 400

    valid = bool(totp.verify(str(code)))
    return jsonify({"ok": True, "valid": valid})

OR JSON in format 
[AUTH] TOTP verify response: 200 { ok: ?, valid: ? }

Requesting code from otp

 const totpRes = await fetch(`http://localhost:5050/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: totpCode })
        });