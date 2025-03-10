from flask import Flask, request, render_template, redirect, make_response
import hashlib
import hmac
import time
import os
import telebot
import jwt
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = int(os.environ["CHAT_ID"])
JWT_KEY = open(os.environ.get("JWT_KEY_PATH"), "rb").read() if os.environ.get("JWT_KEY_PATH") is not None else os.environ.get("JWT_KEY").encode()
UNLOCK_URL = os.environ["UNLOCK_URL"]

app = Flask(__name__)
bot = telebot.TeleBot(BOT_TOKEN, parse_mode=None)
private_key = serialization.load_pem_private_key(
    JWT_KEY, password=None, backend=default_backend()
)

@app.route("/")
def index():
    redirect_uri = request.args.get("redirect_uri")
    if redirect_uri:
        parsed_uri = urlparse(redirect_uri)
        if not parsed_uri.netloc.endswith(".akiba.space"):
            return "Invalid redirect_uri", 400

    token = request.cookies.get("token")
    if token:
        try:
            payload = jwt.decode(token, private_key.public_key(), algorithms=["RS256"])
            if redirect_uri:
                return redirect(redirect_uri, code=303)
            else:
                return render_template("index.html", payload=payload, token=token, unlock_url=UNLOCK_URL, redirect_uri="")
        except Exception as e:
            r = make_response(render_template("index.html", payload=None, token="", unlock_url=UNLOCK_URL, redirect_uri=redirect_uri))
            r.set_cookie("token", "", domain=".akiba.space")
            return r
    else:
        return render_template("index.html", payload=None, token="", unlock_url=UNLOCK_URL, redirect_uri=redirect_uri)

@app.route("/login")
def login():

    redirect_uri = request.args.get("redirect_uri")

    if redirect_uri:
        parsed_uri = urlparse(redirect_uri)
        if not parsed_uri.netloc.endswith(".akiba.space"):
            return "Invalid redirect_uri", 400

    # check telegram params
    args = request.args.to_dict()
    if "redirect_uri" in args:
        del args["redirect_uri"]
    given_hash = args.pop("hash", None)
    if not given_hash:
        return "Missing hash", 403

    args_string = '\n'.join(sorted([f"{k}={v}" for k, v in args.items()]))
    computed_hash = hmac.new(hashlib.sha256(BOT_TOKEN.encode()).digest(), args_string.encode(), hashlib.sha256).hexdigest()
    if given_hash != computed_hash:
        return "Bad hash", 403
    if int(time.time()) - int(args["auth_date"]) > 86400:
        return "Data is outdated", 403
    
    # check user is in channel
    member = bot.get_chat_member(CHAT_ID, int(args["id"]))

    # generate token
    token_payload = {**args, "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=7)}
    if redirect_uri:
        token_payload["redirect_uri"] = redirect_uri
    encoded = jwt.encode(token_payload, private_key, algorithm="RS256")

    r = redirect(redirect_uri if redirect_uri else "/", code=303)
    r.set_cookie(
        "token", 
        encoded, 
        domain=".akiba.space", 
        httponly=True, 
        secure=False, 
        samesite="Lax")
    return r


@app.route("/logout", methods=['POST'])
def logout():
    r = redirect("/", code=303)
    r.set_cookie("token", "", domain=".akiba.space")
    return r

if __name__ == "__main__":
    app.run(debug=True)
