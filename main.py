"""Web Highlights -- Imperal Cloud.

What this app does: every time you select text or capture a screenshot with
the Webbee browser extension and pick an action ("Summarize this", "Explain
this", etc.), an entity is created here recording exactly what you asked and
about what page/context. Once Webbee replies in chat, that reply is attached
to the same entity. This is NOT Notes -- it is a running, browsable log of
"what I asked Webbee about the web, and what she said", kept separate on
purpose (see user directive: don't save to Notes unless explicitly asked).

ARCHITECTURE (why it's shaped this way):

  Browser extension (background.js)
        |  POST /v1/ext/web-highlights/webhook/capture
        |  header: X-Highlights-Secret: <app-scope secret>
        v
  @ext.webhook("capture")            <- runs as system identity "__webhook__"
        |  ctx.store here is a SYSTEM namespace, NOT the user's partition.
        |  ctx.as_user() is NOT available here -- confirmed BOTH by the
        |  concepts/webhooks docs ("ctx.as_user(uid) ... raises in a webhook
        |  handler") AND by a live production test on 2026-08-08 (a direct
        |  write attempt correctly fell back with "delivered":"queued",
        |  proving as_user() raised exactly as documented in practice, not
        |  just on paper). So this handler only ever queues -- it writes a
        |  "pending_captures" system document, tagged with the user's
        |  imperal_id, and returns immediately.
        v
  @ext.schedule("bridge_pending_captures", cron="* * * * *")   <- every 60s
        |  Runs in system context, where ctx.as_user() IS documented-safe.
        |  Fans out over pending_captures, and for each one, writes a real
        |  HighlightAction into THAT user's own store partition via
        |  ctx.as_user(imperal_id).
        v
  chat functions (list_highlights / get_highlight / attach_reply / delete)
        |  Run in full user context -- normal per-user ctx.store reads/writes.
        |  attach_reply is called by Webbee herself, right after answering
        |  in chat, to fill in webbee_reply + flip status to "answered".
        v
  panels: History (left, list) + Detail (center)

WHY THE SCHEDULE DIDN'T RUN FOR OVER A DAY (found + fixed 2026-08-08): six
test captures sat unprocessed in pending_captures for 24+ hours despite
correct code and a valid cron. A same-day detour tried switching the
webhook to write directly via ctx.as_user() (reasoning: maybe as_user()
IS allowed in webhook context after all) -- a live production test proved
that wrong: the direct write fell back to "queued" exactly as the SDK's
as_user() guard predicts (it requires imperal_id == "__system__"; a webhook
gets "__webhook__"). The REAL root cause: per Imperal's publishing docs,
"Once published ... you can surface panels, skeletons, and scheduled
actions" -- @ext.schedule jobs only actually EXECUTE once an extension is
published, not merely `deploy_app`-ed into dev/local install (confirmed:
this app was never in the Marketplace). Fix: reverted the direct-write
detour, bumped to 1.0.1 (bug-fix-only PATCH -- same tools/scopes, per the
semver table this is auto-approved) and submitted for review so the
schedule can actually fire in production.
"""
from __future__ import annotations

import hmac
import json
import logging
from datetime import datetime, timezone

from imperal_sdk import ActionResult, Extension, ChatExtension, ui

from schemas import (
    HighlightAction, HighlightActionList,
    ListHighlightsParams, GetHighlightParams,
    AttachReplyParams, DeleteHighlightParams,
)

log = logging.getLogger(__name__)

ext = Extension(
    "web-highlights",
    version="1.0.1",
    display_name="Web Highlights",
    description=(
        "Web Highlights keeps a running log of everything you ask Webbee "
        "about while browsing -- text you highlight or screenshots you "
        "capture with the Webbee browser extension, plus her reply once "
        "it lands. A dedicated history, separate from Notes."
    ),
    icon="icon.svg",
    actions_explicit=True,
    capabilities=["web-highlights:read", "web-highlights:write"],
)

chat = ChatExtension(
    ext,
    tool_name="web_highlights",
    description="Web Highlights -- browse and manage the log of page highlights/screenshots you asked Webbee about, and attach her replies.",
)

# App-scope secret: ONE value, set once by the developer (you), read
# identically by every call site including webhook context (confirmed in
# the secrets docs: scope="app" is the same ctx.secrets.get() everywhere).
# The browser extension sends this value in a header on every webhook call
# so a stranger who finds the URL can't create fake entries.
ext.secret(
    name="capture_shared_secret",
    description="Shared secret the Webbee browser extension sends on every capture webhook call. Set this once here, then paste the SAME value into the extension's popup.",
    scope="app",
    max_bytes=256,
)(lambda: None)

_PENDING_COLLECTION = "pending_captures"
_ACTIONS_COLLECTION = "highlight_actions"


@ext.health_check
async def health(ctx) -> dict:
    """Static liveness probe -- this app has no external backend to reach,
    so there is nothing to call over ctx.http. ctx.store is deliberately
    NOT touched here: health checks run with no user (ctx.user.imperal_id
    == "__system__"), and the per-user store requires a user context."""
    return {"status": "ok", "version": ext.version}


@ext.on_install
async def on_install(ctx) -> None:
    """Log the install; nothing to provision -- the store collections are
    created lazily on first write, and there is no per-user config needed
    beyond what the browser extension already carries in its own payload."""
    uid = ctx.user.imperal_id if ctx and ctx.user else "system"
    log.info("web-highlights installed for user %s", uid)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ──────────────────────────────────────────────────────────────────────────
# Webhook -- receives the capture the instant you click a bar button.
# Runs as the "__webhook__" system identity: ctx.store here is the SYSTEM
# namespace (not any user's partition), and ctx.as_user() is NOT available
# (raises RuntimeError) -- so this handler only ever queues, never writes
# directly into a user's own HighlightAction collection.
# ──────────────────────────────────────────────────────────────────────────


@ext.webhook("capture", method="POST", secret_header="X-Highlights-Secret")
async def handle_capture(ctx, headers: dict, body: str, query_params: dict) -> dict:
    """Receive one capture event from the Webbee browser extension.

    Expected JSON body:
      {
        "imperal_id": "imp_u_...",     -- whose log this belongs to
        "kind": "text_selection" | "screenshot",
        "instruction": "Summarize this",
        "content_preview": "...",       -- selected text, or a short screenshot description
        "heading": "...",                -- optional
        "context": "...",                -- optional
        "page_title": "...",
        "page_url": "https://...",
      }
    """
    secret = await ctx.secrets.get("capture_shared_secret")
    received = headers.get("x-highlights-secret", "")
    if not secret:
        await ctx.log("capture webhook: capture_shared_secret not configured yet", level="warning")
        return {"status_code": 500, "error": "not configured"}
    if not received or not hmac.compare_digest(received, secret):
        await ctx.log("capture webhook: signature mismatch", level="warning")
        return {"status_code": 401, "error": "invalid secret"}

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        await ctx.log(f"capture webhook: invalid JSON -- {exc}", level="warning")
        return {"status_code": 400, "error": "invalid JSON"}

    imperal_id = str(payload.get("imperal_id", "")).strip()
    if not imperal_id:
        return {"status_code": 400, "error": "missing imperal_id"}

    pending_data = {
        "kind": payload.get("kind", "text_selection"),
        "instruction": payload.get("instruction", ""),
        "content_preview": payload.get("content_preview", "")[:4000],
        "heading": payload.get("heading", ""),
        "context": payload.get("context", "")[:4000],
        "page_title": payload.get("page_title", ""),
        "page_url": payload.get("page_url", ""),
        "created_at": _now_iso(),
    }

    # ctx.as_user() is confirmed unavailable in webhook context (see the
    # architecture note above) -- so this always queues for the schedule
    # bridge below, which is the one place that write is documented-safe.
    doc = await ctx.store.create(_PENDING_COLLECTION, {"imperal_id": imperal_id, **pending_data})
    await ctx.log(f"capture webhook: queued pending capture {doc.id} for {imperal_id}")
    return {"status": "ok", "pending_id": doc.id}


# ──────────────────────────────────────────────────────────────────────────
# Schedule bridge -- every minute, moves queued captures into each user's
# own HighlightAction store. This is the ONLY place ctx.as_user() is used,
# because this is the ONLY handler type the docs confirm it's safe in
# (system context -- @ext.schedule) for writing into a real user's store.
# ──────────────────────────────────────────────────────────────────────────


@ext.webhook("debug_pending", method="GET")
async def debug_pending(ctx, headers: dict, body: str, query_params: dict) -> dict:
    """TEMPORARY diagnostic -- inspect the pending_captures system queue
    directly, to prove whether bridge_pending_captures is actually firing
    on THIS deployed version. Remove once confirmed either way."""
    page = await ctx.store.query(_PENDING_COLLECTION, limit=100)
    return {
        "status": "ok",
        "count": len(page.data),
        "items": [{"id": d.id, "created_at": d.data.get("created_at")} for d in page.data],
    }


async def _bridge_one_pending(user_ctx, pending_data: dict) -> None:
    """Per-user business logic, isolated from the ctx.as_user() fan-out
    machinery -- per the SDK testing guide, this is the piece unit tests
    call directly with a plain MockContext(user_id=...), since ctx.as_user()
    on a real Context wires up more production infra (cache client, gateway
    URL) than a hand-built system context can provide in tests.

    Takes the target user's OWN context (already switched via ctx.as_user)
    and the pending capture's raw data -- writes the real HighlightAction.
    Deletion of the now-bridged pending doc stays in the caller (the system
    context owns the pending_captures collection, not the user context).
    """
    await user_ctx.store.create(_ACTIONS_COLLECTION, {
        "kind": pending_data.get("kind", "text_selection"),
        "instruction": pending_data.get("instruction", ""),
        "content_preview": pending_data.get("content_preview", ""),
        "heading": pending_data.get("heading", ""),
        "context": pending_data.get("context", ""),
        "page_title": pending_data.get("page_title", ""),
        "page_url": pending_data.get("page_url", ""),
        "status": "pending",
        "webbee_reply": "",
        "created_at": pending_data.get("created_at", _now_iso()),
        "answered_at": "",
    })


@ext.schedule("bridge_pending_captures", cron="* * * * *")
async def bridge_pending_captures(ctx) -> None:
    """Move queued webhook captures into each user's own highlight log."""
    page = await ctx.store.query(_PENDING_COLLECTION, limit=100)
    # Always log a heartbeat, even when the queue is empty -- this is the
    # only way to tell "the schedule never ran" apart from "it ran and
    # found nothing", which otherwise look identical from the outside.
    await ctx.log(f"bridge_pending_captures: tick, {len(page.data)} pending item(s)")
    moved = 0
    for pending in page.data:
        imperal_id = pending.data.get("imperal_id", "")
        if not imperal_id:
            await ctx.store.delete(_PENDING_COLLECTION, pending.id)
            continue
        try:
            user_ctx = ctx.as_user(imperal_id)
            await _bridge_one_pending(user_ctx, pending.data)
            await ctx.store.delete(_PENDING_COLLECTION, pending.id)
            moved += 1
        except Exception as exc:
            # Use ctx.log (surfaced in the Developer Portal), not the bare
            # python logger -- a plain log.warning() here is invisible to
            # us and would let this bridge fail silently forever.
            await ctx.log(
                f"bridge_pending_captures: user {imperal_id} failed: {exc}",
                level="error",
            )
    if moved:
        await ctx.log(f"bridge_pending_captures: moved {moved} capture(s) into user logs")


# ──────────────────────────────────────────────────────────────────────────
# Chat functions -- full user context, normal per-user store access.
# ──────────────────────────────────────────────────────────────────────────


def _to_entity(doc) -> HighlightAction:
    d = doc.data
    return HighlightAction(
        id=doc.id,
        title=d.get("instruction", "") or "Highlight",
        kind=d.get("kind", ""),
        instruction=d.get("instruction", ""),
        content_preview=d.get("content_preview", ""),
        heading=d.get("heading", ""),
        context=d.get("context", ""),
        page_title=d.get("page_title", ""),
        page_url=d.get("page_url", ""),
        status=d.get("status", "pending"),
        webbee_reply=d.get("webbee_reply", ""),
        created_at=d.get("created_at", ""),
        answered_at=d.get("answered_at", ""),
    )


@chat.function(
    "list_highlights",
    action_type="read",
    data_model=HighlightActionList,
    description="List your Web Highlights history -- things you asked Webbee about while browsing (text selections or screenshots), newest first. Filter by status ('pending' = no reply yet, 'answered' = has a reply).",
)
async def list_highlights(ctx, params: ListHighlightsParams) -> ActionResult:
    """Return the user's highlight log, newest first, optionally filtered by status."""
    where = {"status": params.status} if params.status else None
    page = await ctx.store.query(_ACTIONS_COLLECTION, where=where, limit=params.limit)
    items = [_to_entity(d) for d in page.data]
    items.sort(key=lambda h: h.created_at, reverse=True)
    return ActionResult.success(
        HighlightActionList(items=items, total=len(items)),
        summary=f"Found {len(items)} highlight(s).",
    )


@chat.function(
    "get_highlight",
    action_type="read",
    data_model=HighlightAction,
    description="Get one Web Highlights entry in full -- the original selection/screenshot context and Webbee's reply if one exists.",
)
async def get_highlight(ctx, params: GetHighlightParams) -> ActionResult:
    """Return one highlight entry in full."""
    doc = await ctx.store.get(_ACTIONS_COLLECTION, params.action_id)
    if not doc:
        return ActionResult.error("No such highlight.", retryable=False)
    return ActionResult.success(_to_entity(doc), summary="Loaded highlight.")


@chat.function(
    "attach_reply",
    action_type="write",
    chain_callable=True,
    effects=["update:highlight_action"],
    event="web-highlights.attach_reply",
    data_model=HighlightAction,
    description="Attach Webbee's reply to a Web Highlights entry, marking it answered. Call this right after replying in chat to something the user pasted from a Web Highlights capture (look for a 'Ref: <id>' line in what they pasted).",
)
async def attach_reply(ctx, params: AttachReplyParams) -> ActionResult:
    """Attach a reply to an existing highlight entry and mark it answered."""
    doc = await ctx.store.get(_ACTIONS_COLLECTION, params.action_id)
    if not doc:
        return ActionResult.error("No such highlight.", retryable=False)
    updated = await ctx.store.update(_ACTIONS_COLLECTION, params.action_id, {
        "webbee_reply": params.reply,
        "status": "answered",
        "answered_at": _now_iso(),
    })
    return ActionResult.success(_to_entity(updated), summary="Reply attached.")


@chat.function(
    "delete_highlight",
    action_type="destructive",
    chain_callable=True,
    effects=["delete:highlight_action"],
    event="web-highlights.delete_highlight",
    data_model=HighlightAction,
    description="Permanently delete one Web Highlights entry.",
)
async def delete_highlight(ctx, params: DeleteHighlightParams) -> ActionResult:
    """Delete one highlight entry permanently."""
    doc = await ctx.store.get(_ACTIONS_COLLECTION, params.action_id)
    if not doc:
        return ActionResult.error("No such highlight.", retryable=False)
    entity = _to_entity(doc)
    await ctx.store.delete(_ACTIONS_COLLECTION, params.action_id)
    return ActionResult.success(entity, summary="Highlight deleted.")


# ──────────────────────────────────────────────────────────────────────────
# Panels
# ──────────────────────────────────────────────────────────────────────────


def _status_badge(status: str) -> ui.Badge:
    return ui.Badge(status, color="green" if status == "answered" else "yellow")


@ext.panel("history", slot="left", title="Web Highlights")
async def history_panel(ctx, **params):
    page = await ctx.store.query(_ACTIONS_COLLECTION, limit=100)
    items = sorted(page.data, key=lambda d: d.data.get("created_at", ""), reverse=True)

    if not items:
        return ui.Empty(
            message="No highlights yet -- select text or capture a screenshot with the Webbee browser extension to start one.",
            icon="🐝",
        )

    list_items = []
    for doc in items:
        d = doc.data
        icon = "📷" if d.get("kind") == "screenshot" else "📝"
        preview = (d.get("content_preview", "") or "")[:80]
        list_items.append(
            ui.ListItem(
                id=doc.id,
                title=d.get("instruction", "Highlight"),
                subtitle=preview,
                icon=icon,
                badge=_status_badge(d.get("status", "pending")),
                on_click=ui.Call("__panel__detail", action_id=doc.id),
            )
        )
    return ui.List(searchable=True, items=list_items)


@ext.panel("detail", slot="center", title="Highlight", center_overlay=True)
async def detail_panel(ctx, **params):
    action_id = params.get("action_id", "")
    if not action_id:
        return ui.Empty(message="Select a highlight from the list.")

    doc = await ctx.store.get(_ACTIONS_COLLECTION, action_id)
    if not doc:
        return ui.Error(message="This highlight no longer exists.")

    d = doc.data
    children = [
        ui.Header(d.get("instruction", "Highlight"), level=2),
        ui.Row(children=[
            _status_badge(d.get("status", "pending")),
            ui.Text(d.get("created_at", ""), variant="caption"),
        ]),
        ui.Divider(),
        ui.Text(d.get("content_preview", ""), variant="body"),
    ]
    if d.get("heading"):
        children.append(ui.KeyValue(items=[{"key": "Section/entity", "value": d["heading"]}]))
    if d.get("context") and d.get("context") != d.get("content_preview"):
        children.append(ui.Section(title="Surrounding context", children=[ui.Text(d["context"])]))
    children.append(
        ui.KeyValue(items=[
            {"key": "Page", "value": d.get("page_title", "")},
            {"key": "URL", "value": d.get("page_url", "")},
        ])
    )
    children.append(ui.Divider())
    if d.get("status") == "answered":
        children.append(ui.Card(title="Webbee's reply", content=ui.Markdown(content=d.get("webbee_reply", ""))))
    else:
        children.append(ui.Alert(message="Waiting for a reply -- paste this into chat and ask Webbee.", type="info"))

    children.append(
        ui.Button("Delete", variant="destructive", icon="Trash2", on_click=ui.Call("delete_highlight", action_id=action_id))
    )
    return ui.Stack(direction="v", gap=3, children=children)
