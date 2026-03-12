import asyncio

from fastapi import FastAPI, Request, Response
from telegram import Update

from main import build_app

app = FastAPI()
telegram_app = build_app()

_initialized = False
_init_lock = asyncio.Lock()


async def ensure_initialized() -> None:
    global _initialized
    if _initialized:
        return
    async with _init_lock:
        if not _initialized:
            await telegram_app.initialize()
            _initialized = True


@app.post("/api/telegram")
async def telegram_webhook(request: Request) -> Response:
    await ensure_initialized()
    payload = await request.json()
    update = Update.de_json(payload, telegram_app.bot)
    await telegram_app.process_update(update)
    return Response(content="OK")


@app.get("/api/telegram")
async def telegram_health() -> Response:
    return Response(content="OK")
