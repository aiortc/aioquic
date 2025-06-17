#
# demo application for http3_server.py
#

import datetime
import os
import traceback
from urllib.parse import urlencode

import aiofiles
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
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

# Define UPLOAD_DIR using environment variable AIOQUIC_UPLOAD_DIR or default,
# and create it
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
    # Local imports are removed as os, aiofiles, PlainTextResponse, HTTPException
    # are available at module level.

    filepath = request.path_params["filepath"]
    if filepath.startswith("upload/"):
        filepath = filepath[len("upload/") :]
        # Ensure filepath is not empty after stripping, or handle if it
        # could be just "upload/"
        if not filepath:  # e.g. if original path was "upload/"
            # Decide behavior: reject, or treat as upload to UPLOAD_DIR root
            # with generated name (current logic handles empty sanitized name)
            # For now, an empty filepath after stripping will be handled by
            # later sanitization.
            pass

    filepath = filepath.lstrip("/")  # This line remains as per instructions

    abs_upload_dir = os.path.abspath(UPLOAD_DIR)

    save_path = os.path.join(abs_upload_dir, filepath)
    abs_save_path = os.path.abspath(save_path)

    # Security Check
    if os.path.commonprefix([abs_save_path, abs_upload_dir]) != abs_upload_dir:
        raise HTTPException(
            status_code=403, detail="Forbidden: Path traversal attempt."
        )

    try:
        parent_dir = os.path.dirname(abs_save_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        async with aiofiles.open(abs_save_path, "wb") as f:
            async for chunk in request.stream():
                await f.write(chunk)

        file_size = os.path.getsize(abs_save_path)
        response_text = (
            f"File '{filepath}' uploaded successfully ({file_size} bytes).\n"
            f"Saved at: {abs_save_path}"
        )
        return PlainTextResponse(response_text, status_code=200)
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error during root dynamic file upload for {filepath}: {e}")  # KEEP THIS
        # Log the full traceback for server-side debugging
        traceback.print_exc()  # KEEP THIS
        raise HTTPException(
            status_code=500, detail=f"Error uploading file '{filepath}': {str(e)}"
        )


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
        Route("/echo", echo, methods=["POST"]),  # Specific POST
        Route("/logs", logs),
        WebSocketRoute("/ws", ws),
        # Add the new root-level POST handler here
        Route("/{filepath:path}", handle_root_post_upload, methods=["POST", "PUT"]),
        # Catch-all for GET (and others if not matched)
        Mount(STATIC_URL, StaticFiles(directory=STATIC_ROOT, html=True)),
    ]
)


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] == "webtransport" and scope["path"] == "/wt":
        await wt(scope, receive, send)
    else:
        await starlette(scope, receive, send)
