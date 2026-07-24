"""Minimal FastAPI wrapper exposing agent-immune as an HTTP service for Sidekick OS."""

from __future__ import annotations

import os
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import List, Optional

from agent_immune import AdaptiveImmuneSystem

app = FastAPI(title="agent-immune", version="0.2.2")

immune = AdaptiveImmuneSystem()


class AssessRequest(BaseModel):
    text: str
    session_id: Optional[str] = "default"


class AssessResponse(BaseModel):
    action: str
    threat_score: float
    reasons: List[str]


@app.get("/health")
async def health():
    return {"ok": True, "version": "0.2.2"}


@app.post("/assess", response_model=AssessResponse)
async def assess(req: AssessRequest):
    result = immune.assess(req.text, session_id=req.session_id or "default")
    return AssessResponse(
        action=result.action.value,
        threat_score=result.threat_score,
        reasons=result.feedback,
    )
