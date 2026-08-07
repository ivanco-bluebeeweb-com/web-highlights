"""Tests for the Web Highlights extension.

Covers all four handler types this app uses, per the documented testing
patterns for each:
  - @ext.webhook  handle_capture       -> MockContext + MockSecretStore
  - @ext.schedule bridge_pending_captures -> hand-built system Context (ctx.as_user)
  - @chat.function list/get/attach_reply/delete -> MockContext
  - @ext.panel history/detail -> MockContext, assert on UINode .type/.props
"""
import json

import pytest
from imperal_sdk.context import Context
from imperal_sdk.testing import MockContext, MockSecretStore, MockStore
from imperal_sdk.types.identity import UserContext

import main as m
from schemas import (
    ListHighlightsParams, GetHighlightParams, AttachReplyParams,
    DeleteHighlightParams,
)


# ──────────────────────────────────────────────────────────────────────────
# Extension registration sanity
# ──────────────────────────────────────────────────────────────────────────


def test_extension_registered():
    assert m.ext.app_id == "web-highlights"
    assert m.ext.display_name and m.ext.display_name != m.ext.app_id
    assert len(m.ext.description) >= 40


# ──────────────────────────────────────────────────────────────────────────
# Webhook: handle_capture
# ──────────────────────────────────────────────────────────────────────────


def _capture_body(**overrides) -> str:
    payload = {
        "imperal_id": "imp_u_test123",
        "kind": "text_selection",
        "instruction": "Summarize this",
        "content_preview": "Some selected sentence.",
        "heading": "Ventilation Systems",
        "context": "Some selected sentence, part of a longer paragraph.",
        "page_title": "Test Page",
        "page_url": "https://example.com/page",
    }
    payload.update(overrides)
    return json.dumps(payload)


@pytest.mark.asyncio
async def test_capture_webhook_delivers_directly_when_as_user_available():
    """Primary path per the decorator-webhook-reference docs: ctx.as_user(uid)
    IS documented as available in webhook context, and live testing on
    2026-08-07/08 proved the schedule-bridge-only design left captures
    stuck in pending_captures for over a day. So handle_capture tries the
    direct write first."""
    ctx = MockContext()
    ctx.secrets = MockSecretStore({"capture_shared_secret": "shh-secret"})
    fake_user_ctx = MockContext(user_id="imp_u_test123")
    ctx.as_user = lambda uid: fake_user_ctx

    result = await m.handle_capture(
        ctx, {"x-highlights-secret": "shh-secret"}, _capture_body(), {}
    )

    assert result == {"status": "ok", "delivered": "direct"}
    assert not ctx.store._data.get("pending_captures")
    page = await fake_user_ctx.store.query(m._ACTIONS_COLLECTION)
    assert len(page.data) == 1
    assert page.data[0].data["instruction"] == "Summarize this"
    assert page.data[0].data["heading"] == "Ventilation Systems"


@pytest.mark.asyncio
async def test_capture_webhook_falls_back_to_pending_queue_if_as_user_fails():
    """If as_user() ever raises (e.g. platform quirk, or this ever runs on
    an older kernel that truly forbids it), nothing is lost -- it queues
    for the schedule bridge exactly like the original design."""
    ctx = MockContext()  # default user_id="test_user" -- not system context,
    # so ctx.as_user() raises RuntimeError here exactly like real webhook
    # context would if as_user() were ever unavailable.
    ctx.secrets = MockSecretStore({"capture_shared_secret": "shh-secret"})

    result = await m.handle_capture(
        ctx, {"x-highlights-secret": "shh-secret"}, _capture_body(), {}
    )

    assert result["status"] == "ok"
    assert "pending_id" in result
    pending = ctx.store._data.get("pending_captures", {})
    assert len(pending) == 1
    doc = next(iter(pending.values()))
    assert doc["imperal_id"] == "imp_u_test123"
    assert doc["instruction"] == "Summarize this"
    assert doc["heading"] == "Ventilation Systems"


@pytest.mark.asyncio
async def test_capture_webhook_wrong_secret_rejected():
    ctx = MockContext()
    ctx.secrets = MockSecretStore({"capture_shared_secret": "shh-secret"})

    result = await m.handle_capture(
        ctx, {"x-highlights-secret": "wrong"}, _capture_body(), {}
    )

    assert result["status_code"] == 401
    assert not ctx.store._data.get("pending_captures")


@pytest.mark.asyncio
async def test_capture_webhook_missing_secret_configured():
    ctx = MockContext()
    ctx.secrets = MockSecretStore({})  # nothing set yet

    result = await m.handle_capture(
        ctx, {"x-highlights-secret": "anything"}, _capture_body(), {}
    )

    assert result["status_code"] == 500


@pytest.mark.asyncio
async def test_capture_webhook_missing_imperal_id_rejected():
    ctx = MockContext()
    ctx.secrets = MockSecretStore({"capture_shared_secret": "shh-secret"})

    body = _capture_body(imperal_id="")
    result = await m.handle_capture(ctx, {"x-highlights-secret": "shh-secret"}, body, {})

    assert result["status_code"] == 400


@pytest.mark.asyncio
async def test_capture_webhook_invalid_json_rejected():
    ctx = MockContext()
    ctx.secrets = MockSecretStore({"capture_shared_secret": "shh-secret"})

    result = await m.handle_capture(
        ctx, {"x-highlights-secret": "shh-secret"}, "not json", {}
    )

    assert result["status_code"] == 400


# ──────────────────────────────────────────────────────────────────────────
# Schedule bridge: bridge_pending_captures (system context + ctx.as_user)
# ──────────────────────────────────────────────────────────────────────────


def _make_system_ctx() -> Context:
    user = UserContext(
        imperal_id="__system__", email="", tenant_id="default",
        role="system", scopes=["*"],
    )
    return Context(user=user, store=MockStore())


@pytest.mark.asyncio
async def test_bridge_one_pending_writes_into_the_target_users_own_store():
    """Per the SDK testing guide: test the per-user helper directly with a
    plain MockContext(user_id=...) rather than the @ext.schedule wrapper --
    ctx.as_user() on a hand-built system Context needs more production
    infra (cache client, gateway URL) than a test context provides."""
    user_ctx = MockContext(user_id="imp_u_alice")

    await m._bridge_one_pending(user_ctx, {
        "kind": "text_selection",
        "instruction": "Explain this",
        "content_preview": "some text",
        "heading": "", "context": "", "page_title": "P", "page_url": "https://p",
        "created_at": "2026-01-01T00:00:00+00:00",
    })

    page = await user_ctx.store.query(m._ACTIONS_COLLECTION)
    assert len(page.data) == 1
    assert page.data[0].data["instruction"] == "Explain this"
    assert page.data[0].data["status"] == "pending"
    assert page.data[0].data["webbee_reply"] == ""


@pytest.mark.asyncio
async def test_bridge_drops_pending_capture_with_no_imperal_id():
    """The no-imperal_id branch never calls ctx.as_user() -- it deletes and
    continues -- so the full decorator wrapper IS safe to exercise here."""
    ctx = _make_system_ctx()
    await ctx.store.create(m._PENDING_COLLECTION, {"imperal_id": "", "instruction": "x"})

    await m.bridge_pending_captures(ctx)

    assert ctx.store._data.get(m._PENDING_COLLECTION, {}) == {}


@pytest.mark.asyncio
async def test_bridge_wrapper_fans_out_and_drains_queue():
    """Exercise the @ext.schedule WRAPPER's own logic (fan-out over pending
    docs, calling as_user, draining the queue on success) without routing
    through the real ctx.as_user() -- which needs live gateway infra a test
    context can't provide. Monkeypatch as_user to hand back a lightweight
    MockContext per user_id, exactly what production as_user() would give
    the handler functionally (a Context scoped to that user's store)."""
    ctx = _make_system_ctx()
    await ctx.store.create(m._PENDING_COLLECTION, {
        "imperal_id": "imp_u_bob",
        "kind": "screenshot",
        "instruction": "Summarize this",
        "content_preview": "screenshot capture",
        "heading": "", "context": "", "page_title": "P2", "page_url": "https://p2",
        "created_at": "2026-01-01T00:00:00+00:00",
    })

    fake_user_ctx = MockContext(user_id="imp_u_bob")
    ctx.as_user = lambda uid: fake_user_ctx

    await m.bridge_pending_captures(ctx)

    # pending queue drained on the SYSTEM context
    assert ctx.store._data.get(m._PENDING_COLLECTION, {}) == {}
    # and the real write landed on the (mocked) target user's context
    page = await fake_user_ctx.store.query(m._ACTIONS_COLLECTION)
    assert len(page.data) == 1
    assert page.data[0].data["instruction"] == "Summarize this"


# ──────────────────────────────────────────────────────────────────────────
# Chat functions
# ──────────────────────────────────────────────────────────────────────────


def _seed_action(ctx, **overrides) -> str:
    data = {
        "kind": "text_selection", "instruction": "Summarize this",
        "content_preview": "preview", "heading": "H", "context": "C",
        "page_title": "T", "page_url": "https://u", "status": "pending",
        "webbee_reply": "", "created_at": "2026-01-01T00:00:00+00:00",
        "answered_at": "",
    }
    data.update(overrides)
    ctx.store._data.setdefault(m._ACTIONS_COLLECTION, {})
    doc_id = f"doc_{len(ctx.store._data[m._ACTIONS_COLLECTION]) + 1}"
    ctx.store._data[m._ACTIONS_COLLECTION][doc_id] = data
    return doc_id


@pytest.mark.asyncio
async def test_list_highlights_returns_all():
    ctx = MockContext()
    _seed_action(ctx, instruction="Summarize this")
    _seed_action(ctx, instruction="Explain this", status="answered")

    result = await m.list_highlights(ctx, ListHighlightsParams(status="", limit=50))

    assert result.status == "success"
    assert result.data.total == 2


@pytest.mark.asyncio
async def test_list_highlights_filters_by_status():
    ctx = MockContext()
    _seed_action(ctx, status="pending")
    _seed_action(ctx, status="answered")

    result = await m.list_highlights(ctx, ListHighlightsParams(status="answered", limit=50))

    assert result.status == "success"
    assert result.data.total == 1
    assert result.data.items[0].status == "answered"


@pytest.mark.asyncio
async def test_get_highlight_found():
    ctx = MockContext()
    doc_id = _seed_action(ctx, instruction="Fact-check this")

    result = await m.get_highlight(ctx, GetHighlightParams(action_id=doc_id))

    assert result.status == "success"
    assert result.data.instruction == "Fact-check this"


@pytest.mark.asyncio
async def test_get_highlight_not_found():
    ctx = MockContext()

    result = await m.get_highlight(ctx, GetHighlightParams(action_id="nope"))

    assert result.status == "error"


@pytest.mark.asyncio
async def test_attach_reply_marks_answered():
    ctx = MockContext()
    doc_id = _seed_action(ctx, status="pending")

    result = await m.attach_reply(
        ctx, AttachReplyParams(action_id=doc_id, reply="Here's the summary...")
    )

    assert result.status == "success"
    assert result.data.status == "answered"
    assert result.data.webbee_reply == "Here's the summary..."
    assert result.data.answered_at


@pytest.mark.asyncio
async def test_attach_reply_missing_entity_errors():
    ctx = MockContext()

    result = await m.attach_reply(ctx, AttachReplyParams(action_id="nope", reply="x"))

    assert result.status == "error"


@pytest.mark.asyncio
async def test_delete_highlight_removes_it():
    ctx = MockContext()
    doc_id = _seed_action(ctx)

    result = await m.delete_highlight(ctx, DeleteHighlightParams(action_id=doc_id))

    assert result.status == "success"
    assert doc_id not in ctx.store._data.get(m._ACTIONS_COLLECTION, {})


# ──────────────────────────────────────────────────────────────────────────
# Panels
# ──────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_history_panel_empty_state():
    ctx = MockContext()

    result = await m.history_panel(ctx)

    assert result.type == "Empty"


@pytest.mark.asyncio
async def test_history_panel_lists_items():
    ctx = MockContext()
    _seed_action(ctx, instruction="Summarize this", kind="text_selection")
    _seed_action(ctx, instruction="Explain this", kind="screenshot", status="answered")

    result = await m.history_panel(ctx)

    assert result.type == "List"
    assert len(result.props["items"]) == 2


@pytest.mark.asyncio
async def test_detail_panel_no_action_id():
    ctx = MockContext()

    result = await m.detail_panel(ctx)

    assert result.type == "Empty"


@pytest.mark.asyncio
async def test_detail_panel_pending_shows_waiting_alert():
    ctx = MockContext()
    doc_id = _seed_action(ctx, status="pending")

    result = await m.detail_panel(ctx, action_id=doc_id)

    serialized = result.to_dict()
    types = [c.get("type") for c in serialized["props"]["children"]]
    assert "Alert" in types


@pytest.mark.asyncio
async def test_detail_panel_answered_shows_reply_card():
    ctx = MockContext()
    doc_id = _seed_action(ctx, status="answered", webbee_reply="The answer is 42.")

    result = await m.detail_panel(ctx, action_id=doc_id)

    serialized = result.to_dict()
    types = [c.get("type") for c in serialized["props"]["children"]]
    assert "Card" in types
