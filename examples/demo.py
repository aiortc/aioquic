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


async def handle_root_post_upload(request):
    import os # ensure os is available
    import aiofiles # ensure aiofiles is available
    from starlette.responses import PlainTextResponse # ensure PlainTextResponse is available
    from starlette.exceptions import HTTPException # ensure HTTPException is available

    # UPLOAD_DIR is globally defined and configured via environment variable AIOQUIC_UPLOAD_DIR
    # It defaults to examples/uploads if the env var is not set.
    # os.makedirs(UPLOAD_DIR, exist_ok=True) is also called globally.

    filepath = request.path_params["filepath"]

    # Sanitize filepath: remove leading slashes to prevent issues with os.path.join if filepath is absolute
    # (though Starlette's :path usually gives a relative path from the mount point)
    filepath = filepath.lstrip("/")

    # Construct the full, absolute path for saving
    # UPLOAD_DIR itself should be an absolute path or resolved to one for reliable security check
    abs_upload_dir = os.path.abspath(UPLOAD_DIR)
    
    # Create the prospective save path
    save_path = os.path.join(abs_upload_dir, filepath)
    abs_save_path = os.path.abspath(save_path) # Normalize the path (resolves .., ., etc.)

    # Security Check: Ensure the normalized save_path is still within abs_upload_dir
    if os.path.commonprefix([abs_save_path, abs_upload_dir]) != abs_upload_dir:
        raise HTTPException(status_code=403, detail="Forbidden: Path traversal attempt.")

    try:
        # Create parent directories if they don't exist
        parent_dir = os.path.dirname(abs_save_path)
        # os.makedirs needs to be robust for when parent_dir is empty (i.e. saving to UPLOAD_DIR root)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
        
        async with aiofiles.open(abs_save_path, "wb") as f:
            async for chunk in request.stream():
                await f.write(chunk)
        
        file_size = os.path.getsize(abs_save_path) # Use abs_save_path as it's normalized
        return PlainTextResponse(f"File '{filepath}' uploaded successfully ({file_size} bytes).\nSaved at: {abs_save_path}", status_code=200)
    except HTTPException: # Re-raise HTTPExceptions (like 403)
        raise
    except Exception as e:
        print(f"Error during root dynamic file upload for {filepath}: {e}") # Server-side log
        raise HTTPException(status_code=500, detail=f"Error uploading file '{filepath}': {str(e)}")


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
        Route("/echo", echo, methods=["POST"]), # Specific POST
        Route("/logs", logs),
        WebSocketRoute("/ws", ws),
        # Add the new root-level POST handler here
        Route("/{filepath:path}", handle_root_post_upload, methods=["POST"]),
        Mount(STATIC_URL, StaticFiles(directory=STATIC_ROOT, html=True)), # Catch-all for GET (and others if not matched)
    ]
)


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] == "webtransport" and scope["path"] == "/wt":
        await wt(scope, receive, send)
    else:
        await starlette(scope, receive, send)
