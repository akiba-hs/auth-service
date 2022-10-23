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
    token = request.cookies.get("token")
    try:
        payload = jwt.decode(token, private_key.public_key(), algorithms=["RS256"])
        return render_template("index.html", payload=payload, token=token, unlock_url=UNLOCK_URL)
    except Exception as e:
        r = make_response(render_template("index.html", payload=None, token=token, unlock_url=UNLOCK_URL))
        r.set_cookie("token", "")
        return r
    

@app.route("/login")
def login():
    # check telegram params
    args = request.args.to_dict()
    given_hash = args['hash']
    del args['hash']
    args_string = '\n'.join(sorted([f"{k}={v}" for k, v in args.items()]))
    computed_hash = hmac.new(hashlib.sha256(BOT_TOKEN.encode()).digest(), args_string.encode(), hashlib.sha256).hexdigest()
    if given_hash != computed_hash:
        return "Bad hash", 403
    if int(time.time()) - int(args["auth_date"]) > 86400:
        return "Data is outdated", 403
    
    # check user is in channel
    member = bot.get_chat_member(CHAT_ID, int(args["id"]))

    # generate token
    encoded = jwt.encode({**args, "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=7)}, private_key, algorithm="RS256")

    r = redirect("/", code=303)
    r.set_cookie("token", encoded)
    return r


@app.route("/logout", methods=['POST'])
def logout():
    r = redirect("/", code=303)
    r.set_cookie("token", "")
    return r