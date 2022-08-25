#!/env/bin/python
# -*- encoding:utf-8 -*-

import secrets
from db_tools import DB
from flask import Flask, redirect, render_template, request, session, send_from_directory
from ratelimit import limits, sleep_and_retry

app = Flask(__name__, template_folder='docs')
app.secret_key = secrets.token_hex(32)
app.db = DB()

_CALLS = 100
_PERIOD = 60


@app.route("/")
@sleep_and_retry
@limits(calls=_CALLS, period=_PERIOD)
def index():
    if 'username' in session:
        ok, response = app.db.get_token(session['username'])
        if not ok:
            return render_template("500.html")
        data = app.db.get_domains(session['username'])
        return render_template("config.html", username=session['username'], token=response['token'], domains=data, limit=len(data))
    return render_template("index.html")


@app.route("/about")
@sleep_and_retry
@limits(calls=_CALLS, period=_PERIOD)
def about():
    return render_template("about.html")


@app.route("/docs")
@sleep_and_retry
@limits(calls=_CALLS, period=_PERIOD)
def docs():
    return render_template("docs.html")


@app.route("/install")
@sleep_and_retry
@limits(calls=_CALLS, period=_PERIOD)
def install():
    return render_template("install.html")


@app.route("/add", methods=["POST"])
@sleep_and_retry
@limits(calls=_CALLS, period=_PERIOD)
def add_domain():
    if 'username' not in session:
        return redirect('/')

    if 'domain' not in request.json.keys():
        return {"reason": "domain missing."} | {"status": 400}

    data = app.db.get_domains(session['username'])
    if len(data) >= 5:
        return {"reason": "can not have more than 5 domains."} | {"status": 400}

    ok, response = app.db.is_domain_valid(
        session['username'], request.json['domain'])
    if not ok:
        return response | {"status": 401}
    return response | {"status": 200}


@app.route("/remove", methods=["GET"])
@sleep_and_retry
@limits(calls=_CALLS, period=_PERIOD)
def remove_domain():
    if ('domain' and 'token') not in request.args.keys():
        return "KO"

    if not app.db.remove_domain(request.args['domain'], request.args['token']):
        return "KO"
    return "OK"


@app.route('/update', methods=["GET"])
@sleep_and_retry
@limits(calls=_CALLS, period=_PERIOD)
def update_domain():
    if ('domain' and 'token' and 'ip') not in request.args.keys():
        return "KO"

    if not len(request.args['ip']):
        ip = request.remote_addr
    else:
        ip = request.args['ip']

    if not app.db.update_domain(request.args['domain'], request.args['token'], ip):
        return "KO"
    return "OK"


@app.route("/login", methods=["GET", "POST"])
@sleep_and_retry
@limits(calls=_CALLS, period=_PERIOD)
def login():
    if request.method == 'POST':
        if ('username' and 'password') not in request.json.keys():
            return {"reason": "username or password missing."} | {"status": 400}

        ok, response = app.db.is_login_valid(
            request.json['username'], request.json['password'])

        if not ok:
            return response | {"status": 401}
        session['username'] = request.json['username']
        return response | {"status": 200}

    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
@sleep_and_retry
@limits(calls=_CALLS, period=_PERIOD)
def register():
    if request.method == 'POST':
        if ('username' and 'password' and 'email') not in request.json.keys():
            return {"reason": "username, password or e-mail missing."} | {"status": 400}

        ok, response = app.db.is_register_valid(
            request.json['username'], request.json['email'], request.json['password'])

        if not ok:
            return response | {"status": 401}
        session['username'] = request.json['username']
        return response | {"status": 200}

    else:
        return render_template("register.html")

# Assets


@app.route("/assets/<path:path>", methods=["GET"])
@sleep_and_retry
@limits(calls=_CALLS, period=_PERIOD)
def serve_static_files(path):
    return send_from_directory('docs/assets', path)
