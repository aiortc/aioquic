#
# demo application for http3_server.py
#

import datetime
import os
import time
import aiofiles
from urllib.parse import urlencode

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocketDisconnect

ROOT = os.path.dirname(__file__)
STATIC_ROOT = os.environ.get("STATIC_ROOT", os.path.join(ROOT, "htdocs"))
STATIC_URL = "/"
LOGS_PATH = os.path.join(STATIC_ROOT, "logs")
QVIS_URL = "https://qvis.quictools.info/"

templates = Jinja2Templates(directory=os.path.join(ROOT, "templates"))

# Define UPLOAD_DIR and create it
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


async def homepage(request):
    """
    Simple homepage.
    """
    await request.send_push_promise("/style.css")
    return templates.TemplateResponse("index.html", {"request": request})


async def echo(request):
    """
    HTTP echo endpoint.
    """
    content = await request.body()
    media_type = request.headers.get("content-type")
    return Response(content, media_type=media_type)


async def logs(request):
    """
    Browsable list of QLOG files.
    """
    logs = []
    for name in os.listdir(LOGS_PATH):
        if name.endswith(".qlog"):
            s = os.stat(os.path.join(LOGS_PATH, name))
            file_url = "https://" + request.headers["host"] + "/logs/" + name
            logs.append(
                {
                    "date": datetime.datetime.utcfromtimestamp(s.st_mtime).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "file_url": file_url,
                    "name": name[:-5],
                    "qvis_url": QVIS_URL
                    + "?"
                    + urlencode({"file": file_url})
                    + "#/sequence",
                    "size": s.st_size,
                }
            )
    return templates.TemplateResponse(
        "logs.html",
        {
            "logs": sorted(logs, key=lambda x: x["date"], reverse=True),
            "request": request,
        },
    )


async def padding(request):
    """
    Dynamically generated data, maximum 50MB.
    """
    size = min(50000000, request.path_params["size"])
    return PlainTextResponse("Z" * size)


async def ws(websocket):
    """
    WebSocket echo endpoint.
    """
    if "chat" in websocket.scope["subprotocols"]:
        subprotocol = "chat"
    else:
        subprotocol = None
    await websocket.accept(subprotocol=subprotocol)

    try:
        while True:
            message = await websocket.receive_text()
            await websocket.send_text(message)
    except WebSocketDisconnect:
        pass


async def upload_file(request):
    import time # ensure time is available
    import os # ensure os is available
    import aiofiles # ensure aiofiles is available

    # Define UPLOAD_DIR inside or ensure it's accessible (global preferred)
    # For safety in subtask, redefine it or ensure it's passed/global
    # This path assumes UPLOAD_DIR was defined globally as per instructions
    CURRENT_ROOT = os.path.dirname(__file__)
    UPLOAD_DIR_FUNC_SCOPE = os.path.join(CURRENT_ROOT, "uploads")
    os.makedirs(UPLOAD_DIR_FUNC_SCOPE, exist_ok=True) # Ensure it exists

    filename = f"upload_{int(time.time())}.dat"
    save_path = os.path.join(UPLOAD_DIR_FUNC_SCOPE, filename)
    
    received_headers = dict(request.headers) # Get headers for debugging

    try:
        async with aiofiles.open(save_path, "wb") as f:
            async for chunk in request.stream():
                await f.write(chunk)
        
        # After successful write, try to get file size with standard os.stat
        file_size = os.path.getsize(save_path)

        return PlainTextResponse(f"File '{filename}' uploaded successfully ({file_size} bytes).\nSaved at: {save_path}\nReceived Headers: {received_headers}", status_code=200)
    except Exception as e:
        # Basic server-side logging
        print(f"Error during file upload for {filename}: {e}") 
        return PlainTextResponse(f"Error uploading file '{filename}': {str(e)}\nReceived Headers: {received_headers}", status_code=500)


async def wt(scope: Scope, receive: Receive, send: Send) -> None:
    """
    WebTransport echo endpoint.
    """
    # accept connection
    message = await receive()
    assert message["type"] == "webtransport.connect"
    await send({"type": "webtransport.accept"})

    # echo back received data
    while True:
        message = await receive()
        if message["type"] == "webtransport.datagram.receive":
            await send(
                {
                    "data": message["data"],
                    "type": "webtransport.datagram.send",
                }
            )
        elif message["type"] == "webtransport.stream.receive":
            await send(
                {
                    "data": message["data"],
                    "stream": message["stream"],
                    "type": "webtransport.stream.send",
                }
            )


starlette = Starlette(
    routes=[
        Route("/", homepage),
        Route("/{size:int}", padding),
        Route("/echo", echo, methods=["POST"]),
        Route("/logs", logs),
        Route("/upload", upload_file, methods=["POST"]),
        WebSocketRoute("/ws", ws),
        Mount(STATIC_URL, StaticFiles(directory=STATIC_ROOT, html=True)),
    ]
)


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] == "webtransport" and scope["path"] == "/wt":
        await wt(scope, receive, send)
    else:
        await starlette(scope, receive, send)
