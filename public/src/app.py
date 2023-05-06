import hashlib
import logging
import os
from urllib.parse import urlparse
import json
import requests
import datetime

from flask import (
    Flask,
    render_template,
    render_template_string,
    request,
    jsonify,
    session,
    redirect,
    abort
)
from pymongo import MongoClient
from weasyprint import HTML

def send_log(data):
    params = {"logs": json.dumps(data)} 
    r = requests.get(f"http://{os.getenv('LOG_SERVER_HOST')}/logs", params=params)
    return r.json()["result"]

log = logging.getLogger(__name__)

logging.info("")
app = Flask(__name__, static_url_path="/static/")
app.secret_key = os.urandom(32)

# Set up noSQL database
client = MongoClient("mongodb://db:27017")
db = client["research03"]
tab = db["users"]
tab.delete_many({})
admin_cred = {"username": "admin", "password": str(os.urandom(32))}
tab.insert_one(admin_cred)


@app.route("/", methods=["GET"])
def index_page():
    username = ""
    if "username" in session.keys():
        username = session["username"]

    return render_template("index.html", username=username)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        username = ""
        if "username" in session.keys():
            username = session["username"]
        return render_template("login.html", username=username)
    else:
        data = request.json
        if "username" in data.keys() and "password" in data.keys():
            login_cred = {"username": data["username"], "password": data["password"]}
            find_cred = dict()

            for i in tab.find(login_cred):
                find_cred = i
                break

            if "username" in find_cred.keys():
                session["username"] = find_cred["username"]
                result = {"status": 200, "msg": "Authenticated!", "return": "/"}

            else:
                result = {
                    "status": 403,
                    "msg": "Please check username or password.",
                    "return": "/login",
                }

        else:
            result = {
                "status": 403,
                "msg": "Missing username or password.",
                "return": "/login",
            }

        return jsonify(result)


@app.route("/converter", methods=["GET", "POST"])
def converter_page():
    if "username" not in session.keys():
        return redirect("/login")

    if request.method == "GET":
        username = ""
        if "username" in session.keys():
            username = session["username"]
        return render_template("converter.html", username=username)
    else:
        data = request.json
        if "url" in data.keys():
            url = data["url"]
            if urlparse(url).scheme.lower() not in ["http", "https"]:
                result = {"status": 403, "msg": "You can only use http or https."}
            else:
                filename = hashlib.sha256(os.urandom(16)).hexdigest()
                start_time = str(datetime.datetime.now())
                HTML(url).write_pdf(f"static/output/{filename}.pdf")
                data = {
                    "time": start_time,
                    "ip": request.remote_addr
                }
                send_log(data)
                result = {
                    "status": 200,
                    "output": f'<a href="/static/output/{filename}.pdf">static/output/{filename}.pdf</a>',
                }
        else:
            result = {"status": 403}
        return jsonify(result)


@app.errorhandler(404)
def not_found(e):
    return f"404 Not Found: {request.path}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False)
