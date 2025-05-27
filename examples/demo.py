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
    import os 
    import aiofiles 
    from starlette.responses import PlainTextResponse 
    from starlette.exceptions import HTTPException 

    # Ensure UPLOAD_DIR is accessible (it's a global in demo.py)
    # Print statements will be used for logging as per plan.

    print(f"HRP_UPLOAD: Entered handle_root_post_upload.")
    
    filepath = request.path_params["filepath"]
    print(f"HRP_UPLOAD: filepath from URL = '{filepath}'")
    print(f"HRP_UPLOAD: Global UPLOAD_DIR = '{UPLOAD_DIR}'")

    filepath = filepath.lstrip("/")
    print(f"HRP_UPLOAD: Sanitized filepath = '{filepath}'")

    abs_upload_dir = os.path.abspath(UPLOAD_DIR)
    print(f"HRP_UPLOAD: Absolute UPLOAD_DIR = '{abs_upload_dir}'")
    
    save_path = os.path.join(abs_upload_dir, filepath) # Use abs_upload_dir to ensure join is safe if filepath is somehow absolute (though lstrip should prevent)
    abs_save_path = os.path.abspath(save_path)
    print(f"HRP_UPLOAD: Calculated absolute save_path = '{abs_save_path}'")

    # Security Check
    if os.path.commonprefix([abs_save_path, abs_upload_dir]) != abs_upload_dir:
        print(f"HRP_UPLOAD: Security check FAILED. Common prefix mismatch.")
        print(f"HRP_UPLOAD: commonprefix is '{os.path.commonprefix([abs_save_path, abs_upload_dir])}'")
        raise HTTPException(status_code=403, detail="Forbidden: Path traversal attempt.")
    print(f"HRP_UPLOAD: Security check PASSED.")

    try:
        parent_dir = os.path.dirname(abs_save_path)
        print(f"HRP_UPLOAD: Parent directory for save_path = '{parent_dir}'")
        if parent_dir and not os.path.exists(parent_dir):
            print(f"HRP_UPLOAD: Creating parent directory: '{parent_dir}'")
            os.makedirs(parent_dir, exist_ok=True)
        else:
            print(f"HRP_UPLOAD: Parent directory '{parent_dir}' already exists or is not needed.")
        
        print(f"HRP_UPLOAD: Attempting to open file for writing: '{abs_save_path}'")
        async with aiofiles.open(abs_save_path, "wb") as f:
            print(f"HRP_UPLOAD: File opened successfully. Streaming content...")
            async for chunk in request.stream():
                await f.write(chunk)
            print(f"HRP_UPLOAD: Content streamed successfully.")
        
        file_size = os.path.getsize(abs_save_path)
        print(f"HRP_UPLOAD: File size: {file_size} bytes.")
        response_text = f"File '{filepath}' uploaded successfully ({file_size} bytes).\nSaved at: {abs_save_path}"
        print(f"HRP_UPLOAD: Sending success response: '{response_text}'")
        return PlainTextResponse(response_text, status_code=200)
    except HTTPException:
        print(f"HRP_UPLOAD: Re-raising HTTPException.")
        raise 
    except Exception as e:
        print(f"HRP_UPLOAD: Exception during file upload for '{filepath}': {e}")
        # Log the full traceback for server-side debugging
        import traceback
        traceback.print_exc()
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
        Route("/{filepath:path}", handle_root_post_upload, methods=["POST", "PUT"]),
        Mount(STATIC_URL, StaticFiles(directory=STATIC_ROOT, html=True)), # Catch-all for GET (and others if not matched)
    ]
)


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] == "webtransport" and scope["path"] == "/wt":
        await wt(scope, receive, send)
    else:
        await starlette(scope, receive, send)
