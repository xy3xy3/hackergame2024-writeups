from typing import Any, Callable
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starsessions import CookieStore, load_session, SessionMiddleware
from streaming_form_data import StreamingFormDataParser
import streaming_form_data
from streaming_form_data.targets import BaseTarget
from streaming_form_data.validators import MaxSizeValidator
import base64
import OpenSSL
import hashlib
import os
import asyncio
from pathlib import Path
from .secret import secret_key


session_store = CookieStore(secret_key=secret_key)

flag_rule = os.environ["hackergame_flag_rule"]
hackergame_secret_key = os.environ["hackergame_secret_key"]
hackergame_secret_size = int(os.environ["hackergame_secret_size"])
nc_host = os.environ["hackergame_nc_host"]
nc_port = int(os.environ["hackergame_nc_port"])

app = FastAPI(docs_url=None, openapi_url=None)

with open(Path(__file__).parent / "cert.pem") as f:
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())

app.mount("/static", StaticFiles(directory=(Path(__file__).parent / "static")), name="static")

templates = Jinja2Templates(directory=(Path(__file__).parent / "templates"))

async def check_token(request: Request, call_next):
    if request.url.path.startswith('/static/'):
        return await call_next(request)
    query_token = request.query_params.get('token')
    await load_session(request)

    if query_token:
        try:
            id, sig = query_token.split(":", 1)
            sig = base64.b64decode(sig, validate=True)
            OpenSSL.crypto.verify(cert, sig, id.encode(), "sha256")
            request.session['token'] = query_token
        except Exception:
            request.session.clear()
            print("Invalid token")
        return RedirectResponse(url=app.url_path_for('index'))
    if not request.session.get("token"):
        return templates.TemplateResponse(request=request, name="error.html", status_code=403)
    return await call_next(request)

app.add_middleware(BaseHTTPMiddleware, dispatch=check_token)
app.add_middleware(SessionMiddleware, store=session_store, lifetime=0, cookie_https_only=False)

def get_user_id(request):
    return request.session['token'].split(":", 1)[0]

def generate_flag(token):
    functions = {}
    for method in "md5", "sha1", "sha256":
        def f(s, method=method):
            return getattr(hashlib, method)(s.encode()).hexdigest()
        functions[method] = f
    flag = eval(flag_rule, functions, {"token": token})
    return flag

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

class SecretGenerator:
    def __init__(self, token):
        image = hackergame_secret_key.strip().encode() + b'\0' + token.strip().encode()
        image2 = hashlib.sha256(image).digest()
        seed = hashlib.sha256(image2).digest()
        shake256 = hashlib.shake_256(seed)
        self.shake256 = shake256

    def __call__(self, size):
        return self.shake256.digest(size)

class ComparingTarget(BaseTarget):
    def __init__(self, ref_secret: bytes, validator: Callable[..., Any] | None = None):
        super().__init__(validator)
        self.received = 0
        self.same = True
        self.ref_secret = ref_secret
        self.secret_size = len(ref_secret)

    def on_data_received(self, chunk: bytes):
        len_chunk = len(chunk)
        if self.received + len_chunk > self.secret_size:
            self.received += len_chunk
            self.same = False
            return
        ref_chunk = self.ref_secret[self.received:self.received + len_chunk]
        self.received += len_chunk
        if ref_chunk != chunk:
            self.same = False

    @property
    def valid(self):
        return self.received == self.secret_size and self.same

@app.post("/submit", response_class=JSONResponse)
async def submit(request: Request):
    await load_session(request)
    token = request.session["token"]

    try:
        comparer = ComparingTarget(SecretGenerator(token)(hackergame_secret_size), validator=MaxSizeValidator(hackergame_secret_size))
        parser = StreamingFormDataParser(headers=request.headers)
        parser.register('file', comparer)
        async for chunk in request.stream():
            parser.data_received(chunk)


    except streaming_form_data.validators.ValidationError:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f'Maximum file size limit exceeded')
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='There was an error uploading the file')
    if not comparer.valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
            detail='Invalid Secret')
    return {"flag": generate_flag(token)}



@app.websocket("/connect")
async def connect(websocket: WebSocket):
    await load_session(websocket)
    token = websocket.session["token"]
    tcp_reader, tcp_writer = await asyncio.open_connection(nc_host, nc_port)
    buf = b""
    while True:
        buf += await tcp_reader.readuntil(b"\n")
        if buf == b"Please input your token: \n":
            break
    tcp_writer.write(token.encode() + b"\n")
    await tcp_writer.drain()

    await websocket.accept()

    async def client_to_server():
        try:
            while True:
                data = await websocket.receive_bytes()
                if not data:
                    tcp_writer.close()
                    break
                tcp_writer.write(data)
                await tcp_writer.drain()
        except asyncio.CancelledError:
            return
        except WebSocketDisconnect:
            return
        finally:
            tcp_writer.close()

    async def server_to_client():
        try:
            while True:
                data = await tcp_reader.read(4096)
                if not data:
                    break
                await websocket.send_bytes(data)
        except asyncio.CancelledError:
            return
        except WebSocketDisconnect:
            return

    server_to_client_task = asyncio.create_task(server_to_client())
    client_to_server_task = asyncio.create_task(client_to_server())
    tasks = [server_to_client_task, client_to_server_task]
    _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    asyncio.gather(*tasks)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app)