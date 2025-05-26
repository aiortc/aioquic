#
# demo application for http3_server.py
#

import datetime
import os
import time
import aiofiles
import cgi
import uuid
from urllib.parse import urlencode

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocketDisconnect
from starlette.exceptions import HTTPException

ROOT = os.path.dirname(__file__)
STATIC_ROOT = os.environ.get("STATIC_ROOT", os.path.join(ROOT, "htdocs"))
STATIC_URL = "/"
LOGS_PATH = os.path.join(STATIC_ROOT, "logs")
QVIS_URL = "https://qvis.quictools.info/"

templates = Jinja2Templates(directory=os.path.join(ROOT, "templates"))

# Define UPLOAD_DIR using environment variable AIOQUIC_UPLOAD_DIR or default, and create it
UPLOAD_DIR = os.environ.get("AIOQUIC_UPLOAD_DIR", os.path.join(ROOT, "uploads"))
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
    # These imports are fine here as they are specific to this function's logic
    import cgi
    import os
    import time
    import uuid
    import aiofiles # ensure aiofiles is available
    from starlette.responses import PlainTextResponse # ensure PlainTextResponse is available
    from starlette.exceptions import HTTPException # ensure HTTPException is available

    filename_to_save = None
    content_disposition_header = request.headers.get("content-disposition")

    if content_disposition_header:
        _, params = cgi.parse_header(content_disposition_header)
        if "filename" in params:
            # It's important to sanitize this filename
            filename_to_save = os.path.basename(params["filename"])

    if not filename_to_save: # If no header, no filename in header, or basename resulted in empty
        filename_to_save = f"upload_{int(time.time())}_{uuid.uuid4().hex[:8]}.dat"
    
    # Final safety check for empty filename after basename (e.g. if input was just "/")
    if not filename_to_save:
        filename_to_save = f"default_{int(time.time())}_{uuid.uuid4().hex[:8]}.dat"

    save_path = os.path.join(UPLOAD_DIR, filename_to_save)
    
    # Security check: ensure the final save_path is still within UPLOAD_DIR
    # This is a redundant check if os.path.basename() is used correctly and UPLOAD_DIR is absolute,
    # but defense in depth is good.
    abs_upload_dir = os.path.abspath(UPLOAD_DIR)
    abs_save_path = os.path.abspath(save_path)

    if os.path.commonprefix([abs_save_path, abs_upload_dir]) != abs_upload_dir:
        # This should ideally not be reached if basename and UPLOAD_DIR are handled correctly
        print(f"Security alert: Attempted save path '{abs_save_path}' is outside UPLOAD_DIR '{abs_upload_dir}'")
        raise HTTPException(status_code=403, detail="Forbidden: Invalid save path.")

    try:
        async with aiofiles.open(save_path, "wb") as f:
            async for chunk in request.stream():
                await f.write(chunk)
        
        file_size = os.path.getsize(save_path)
        return PlainTextResponse(f"File '{filename_to_save}' uploaded successfully ({file_size} bytes).\nSaved at: {save_path}", status_code=200)
    except Exception as e:
        print(f"Error during file upload for {filename_to_save}: {e}")
        raise HTTPException(status_code=500, detail=f"Error uploading file: {str(e)}")


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
        # Route("/files/{filepath:path}", handle_dynamic_upload, methods=["POST"]), # Removed
        WebSocketRoute("/ws", ws),
        Mount(STATIC_URL, StaticFiles(directory=STATIC_ROOT, html=True)),
    ]
)


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] == "webtransport" and scope["path"] == "/wt":
        await wt(scope, receive, send)
    else:
        await starlette(scope, receive, send)
