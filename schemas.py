"""Pydantic params models + SDL entity contracts for Web Highlights.

All params models are module-scope (V17 federal invariant).
Entities/EntityLists follow the read-tool contract (V23): a single record
is an sdl.Entity subclass, a list result is sdl.EntityList[T] -- never a
bare dict wrapper.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from imperal_sdk import sdl

# ──────────────────────────────────────────────────────────────────────────
# Domain entity
# ──────────────────────────────────────────────────────────────────────────


class HighlightAction(sdl.Entity):
    """One thing the user asked Webbee about a web page -- a text selection
    or a screenshot -- plus Webbee's reply once it exists.

    Lives in the USER's own store partition (collection "highlight_actions"),
    written there only by the schedule bridge (from the webhook's pending
    queue) or by chat functions running in the user's own context -- never
    directly by the webhook, which only ever sees the system namespace.
    """
    kind: str = ""  # "text_selection" | "screenshot"
    instruction: str = ""  # e.g. "Summarize this"
    content_preview: str = ""  # selected text, or a short description for a screenshot
    heading: str = ""  # nearest heading/entity name above the selection, if any
    context: str = ""  # surrounding paragraph/block, if any
    page_title: str = ""
    page_url: str = ""
    status: str = "pending"  # "pending" | "answered"
    webbee_reply: str = ""
    created_at: str = ""
    answered_at: str = ""


class HighlightActionList(sdl.EntityList[HighlightAction]):
    pass


# ──────────────────────────────────────────────────────────────────────────
# Chat function params
# ──────────────────────────────────────────────────────────────────────────


class ListHighlightsParams(BaseModel):
    status: str = Field(
        default="",
        description="Optional filter: 'pending' or 'answered'. Empty = all.",
    )
    limit: int = Field(default=20, ge=1, le=100, description="Max items to return")


class GetHighlightParams(BaseModel):
    action_id: str = Field(description="HighlightAction id, from list_highlights")


class AttachReplyParams(BaseModel):
    action_id: str = Field(description="HighlightAction id to attach a reply to")
    reply: str = Field(description="Webbee's reply text to attach to this highlight", min_length=1)


class DeleteHighlightParams(BaseModel):
    action_id: str = Field(description="HighlightAction id to permanently delete")
