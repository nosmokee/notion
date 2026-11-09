#!/usr/bin/env python3
"""ncodex relay — посредник с постоянным адресом между Notion и ncodex на компьютере.

    Notion ──HTTPS──▶ relay (этот сервер) ◀──WebSocket── ncodex на компьютере

Компьютер сам подключается к relay исходящим соединением, поэтому ему не нужны белый IP,
проброс портов и туннели, а адрес для Notion не меняется. Relay ничего не хранит: запрос Notion
уходит в ncodex, ответ — обратно. Токен в ссылке Notion проверяет сам ncodex.

Переменные окружения:
  RELAY_SECRET     секрет из окна ncodex (Настройки → Туннель → Свой сервер), не короче 24 символов
  PORT             порт (Render задаёт сам; по умолчанию 8080)
  REQUEST_TIMEOUT  сколько ждать ответа компьютера, секунд (по умолчанию 300)
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import itertools
import json
import logging
import os
import re
import time

from aiohttp import WSMsgType, web
from multidict import CIMultiDict

RELAY_VERSION = "1.0"
SECRET = os.environ.get("RELAY_SECRET", "").strip()
PORT = int(os.environ.get("PORT") or 8080)
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT") or 300)
MAX_BODY = 32 * 1024 * 1024
MAX_PENDING = 64
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te",
       "trailer", "trailers", "transfer-encoding", "upgrade", "host", "content-length"}
# заголовки прокси хостинга и служебные заголовки ncodex дальше не пропускаем
STRIP = ("x-forwarded-", "x-real-ip", "cf-", "true-client-ip", "forwarded", "x-ncodex-", "rndr-",
         "x-request-start", "x-render-")
OFFLINE = ("Компьютер не в сети: ncodex на нём не запущен или ещё не подключился к своему серверу. "
           "Запусти ncodex (или подожди минуту) и повтори.")

log = logging.getLogger("ncodex-relay")
IDS = itertools.count(1)


class Agent:
    """Подключённый ncodex: WebSocket и запросы, которые ждут его ответа."""

    def __init__(self, ws: web.WebSocketResponse, version: str, peer: str):
        self.ws = ws
        self.version = version
        self.peer = peer
        self.since = time.time()
        self.pending: dict[str, asyncio.Future] = {}
        self.lock = asyncio.Lock()

    async def send(self, data: dict) -> None:
        async with self.lock:
            await self.ws.send_str(json.dumps(data, ensure_ascii=False))

    def fail_all(self, why: str) -> None:
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError(why))
        self.pending.clear()


AGENT: dict[str, Agent | None] = {"cur": None}


def secret_ok() -> bool:
    return len(SECRET) >= 24


def authorized(request: web.Request) -> bool:
    h = request.headers.get("Authorization", "")
    tok = h[7:].strip() if h[:7].lower() == "bearer " else ""
    return secret_ok() and hmac.compare_digest(tok.encode(), SECRET.encode())


def client_ip(request: web.Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    ip = xff.split(",")[0].strip() if xff else ""
    return (ip or request.remote or "unknown")[:64]


def masked(path: str) -> str:
    """Путь для журнала: токен из ссылки Notion не пишем."""
    return re.sub(r"(/mcp/)[^/?#]+", r"\1***", path).split("?")[0][:200]


def rpc_error(status: int, text: str) -> web.Response:
    return web.json_response({"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": text}},
                             status=status, headers={"Cache-Control": "no-store"})


def offline(request: web.Request) -> web.Response:
    if request.path.startswith("/mcp"):
        return rpc_error(503, OFFLINE)
    return web.Response(status=503, text="ncodex relay работает. " + OFFLINE + "\n",
                        headers={"Cache-Control": "no-store"})


async def ping(request: web.Request) -> web.Response:
    """Проверка живости (Render health check) и «будильник», которым ncodex не даёт серверу уснуть."""
    return web.Response(text="ok", headers={"Cache-Control": "no-store"})


async def status(request: web.Request) -> web.Response:
    if not authorized(request):
        await asyncio.sleep(0.5)
        return web.json_response({"error": "wrong secret"}, status=401)
    a = AGENT["cur"]
    return web.json_response({"app": "ncodex-relay", "relay": RELAY_VERSION, "agent": a is not None,
                              "agent_version": a.version if a else None,
                              "connected_for": int(time.time() - a.since) if a else None,
                              "pending": len(a.pending) if a else 0})


async def agent_ws(request: web.Request) -> web.StreamResponse:
    if not secret_ok():
        return web.Response(status=503, text="RELAY_SECRET не задан или короче 24 символов")
    if not authorized(request):
        log.warning("отклонено подключение с неверным секретом (%s)", client_ip(request))
        await asyncio.sleep(1)
        return web.Response(status=401, text="wrong secret")
    ws = web.WebSocketResponse(heartbeat=25, max_msg_size=MAX_BODY * 2, compress=False)
    await ws.prepare(request)
    agent = Agent(ws, request.headers.get("X-Ncodex-Version", "?")[:32], client_ip(request))
    old, AGENT["cur"] = AGENT["cur"], agent
    if old is not None:
        old.fail_all("replaced")
        await old.ws.close(code=4000, message=b"replaced by a newer connection")
    log.info("компьютер подключился (ncodex %s)", agent.version)
    try:
        await agent.send({"t": "welcome", "relay": RELAY_VERSION})
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    d = json.loads(msg.data)
                except ValueError:
                    continue
                if isinstance(d, dict) and d.get("t") == "res":
                    fut = agent.pending.pop(str(d.get("id")), None)
                    if fut is not None and not fut.done():
                        fut.set_result(d)
            elif msg.type == WSMsgType.ERROR:
                break
    finally:
        if AGENT["cur"] is agent:
            AGENT["cur"] = None
            log.info("компьютер отключился")
        agent.fail_all("disconnected")
    return ws


async def forward(request: web.Request) -> web.StreamResponse:
    agent = AGENT["cur"]
    if agent is None or agent.ws.closed:
        return offline(request)
    if len(agent.pending) >= MAX_PENDING:
        return rpc_error(503, "Слишком много одновременных запросов к компьютеру — повтори чуть позже.")
    try:
        body = await request.read()
    except web.HTTPRequestEntityTooLarge:
        return rpc_error(413, "Слишком большой запрос.")
    headers = [[k, v] for k, v in request.headers.items()
               if k.lower() not in HOP and not k.lower().startswith(STRIP)]
    headers.append(["X-Forwarded-For", client_ip(request)])
    headers.append(["X-Forwarded-Proto", request.headers.get("X-Forwarded-Proto", request.scheme)])
    rid = str(next(IDS))
    fut = asyncio.get_running_loop().create_future()
    agent.pending[rid] = fut
    t0 = time.monotonic()
    try:
        await agent.send({"t": "req", "id": rid, "m": request.method, "p": request.path_qs, "h": headers,
                          "b": base64.b64encode(body).decode()})
        d = await asyncio.wait_for(fut, REQUEST_TIMEOUT)
    except asyncio.TimeoutError:
        log.warning("%s %s: компьютер не ответил за %d с", request.method, masked(request.path), REQUEST_TIMEOUT)
        return rpc_error(504, f"Компьютер не ответил за {int(REQUEST_TIMEOUT)} с.")
    except (ConnectionError, RuntimeError):
        return rpc_error(502, "Компьютер отключился, не успев ответить. Повтори через несколько секунд.")
    finally:
        agent.pending.pop(rid, None)
    try:
        code = int(d.get("s") or 502)
        data = base64.b64decode(d.get("b") or "")
    except (TypeError, ValueError):
        code, data = 502, b""
    out: CIMultiDict = CIMultiDict()
    for item in d.get("h") or []:
        if isinstance(item, list) and len(item) == 2 and str(item[0]).lower() not in HOP:
            out.add(str(item[0]), str(item[1]))
    log.info("%s %s → %s, %.0f мс", request.method, masked(request.path), code, (time.monotonic() - t0) * 1000)
    return web.Response(status=code, body=data, headers=out)


def make_app() -> web.Application:
    app = web.Application(client_max_size=MAX_BODY)
    app.router.add_get("/_ncodex/ping", ping)
    app.router.add_get("/_ncodex/status", status)
    app.router.add_get("/_ncodex/agent", agent_ws)
    app.router.add_route("*", "/{tail:.*}", forward)
    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    if secret_ok():
        log.info("ncodex relay %s, порт %d", RELAY_VERSION, PORT)
    else:
        log.error("RELAY_SECRET не задан или короче 24 символов — компьютер не сможет подключиться. "
                  "Скопируй секрет из окна ncodex (Настройки → Туннель → Свой сервер) в переменные окружения.")
    web.run_app(make_app(), host="0.0.0.0", port=PORT, access_log=None, print=None)


if __name__ == "__main__":
    main()
