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
from starlette.exceptions import HTTPException

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


async def handle_dynamic_upload(request):
    import os # ensure os is available
    import aiofiles # ensure aiofiles is available
    from starlette.responses import PlainTextResponse # ensure PlainTextResponse is available
    from starlette.exceptions import HTTPException # ensure HTTPException is available

    # UPLOAD_DIR should be globally defined and created
    # For robustness in subtask, re-reference or ensure it's accessible
    CURRENT_ROOT = os.path.dirname(__file__)
    _UPLOAD_DIR = os.path.join(CURRENT_ROOT, "uploads") # Use a local alias to avoid modifying global UPLOAD_DIR if any scope issues

    filepath = request.path_params["filepath"]

    # Sanitize filepath: remove leading slashes to prevent absolute paths if filepath somehow captures them
    # (though Starlette's :path usually doesn't include the leading slash of its capture)
    filepath = filepath.lstrip("/")

    # Construct the full path
    # os.path.join will correctly handle concatenating _UPLOAD_DIR and filepath
    # even if filepath is multi-level (e.g., "some/folder/file.txt")
    full_path = os.path.join(_UPLOAD_DIR, filepath)

    # Security Check: Normalize the path and ensure it's within UPLOAD_DIR
    # os.path.abspath resolves '..' and other relative components
    abs_upload_dir = os.path.abspath(_UPLOAD_DIR)
    abs_full_path = os.path.abspath(full_path)

    if os.path.commonprefix([abs_full_path, abs_upload_dir]) != abs_upload_dir:
        # Path traversal attempt
        raise HTTPException(status_code=403, detail="Forbidden: Path traversal attempt.")

    try:
        # Create parent directories if they don't exist
        parent_dir = os.path.dirname(abs_full_path)
        if not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
        
        async with aiofiles.open(abs_full_path, "wb") as f:
            async for chunk in request.stream():
                await f.write(chunk)
        
        file_size = os.path.getsize(abs_full_path)
        return PlainTextResponse(f"File '{filepath}' uploaded successfully ({file_size} bytes).\nSaved at: {abs_full_path}", status_code=200)
    except HTTPException:
        raise # Re-raise HTTPException (like the 403)
    except Exception as e:
        # Log the exception on the server for debugging
        print(f"Error during dynamic file upload for {filepath}: {e}")
        # Return a generic server error to the client
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
        # The old /upload route is removed as per instructions
        # Route("/upload", upload_file, methods=["POST"]), 
        Route("/files/{filepath:path}", handle_dynamic_upload, methods=["POST"]),
        WebSocketRoute("/ws", ws),
        Mount(STATIC_URL, StaticFiles(directory=STATIC_ROOT, html=True)),
    ]
)


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] == "webtransport" and scope["path"] == "/wt":
        await wt(scope, receive, send)
    else:
        await starlette(scope, receive, send)
