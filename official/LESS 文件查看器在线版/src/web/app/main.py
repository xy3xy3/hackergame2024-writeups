from flask import Flask, request, make_response, render_template, session, redirect, url_for
import socket
import os
import base64
import OpenSSL
from secret import secret_key

app = Flask(__name__)
app.secret_key = secret_key

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

with open("./cert.pem") as f:
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())


@app.before_request
def check():
    if request.path.startswith("/static/"):
        return
    if request.args.get("token"):
        try:
            token = request.args.get("token")
            id, sig = token.split(":", 1)
            sig = base64.b64decode(sig, validate=True)
            OpenSSL.crypto.verify(cert, sig, id.encode(), "sha256")
            session["token"] = token
        except Exception:
            session["token"] = None
        return redirect(url_for("index"))
    if session.get("token") is None:
        return make_response(render_template("error.html"), 403)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        token = session["token"]
        files = request.files.getlist('files')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((os.environ["nc_host"], int(os.environ["nc_port"])))

        buf = b""
        while True:
            buf += s.recv(4096)
            if buf == b"Please input your token: \n":
                break
        s.sendall(token.encode() + b"\n")

        buf = b""
        while True:
            buf += s.recv(4096)
            if not b"Files:".startswith(buf):
                break

        if buf == b"Files:\n":
            for file in files:
                if file.filename:
                    s.sendall(base64.b64encode(file.filename.encode()) + b"\n")
                    s.sendall(base64.b64encode(file.read()) + b"\n")
            s.sendall(b'#EOF\n')
            buf = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                buf += data
        return render_template('index.html', result=buf.decode())
    else:
        return render_template('index.html', result='')
