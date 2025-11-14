"""Minimal HackGPT relay API wired for n8n webhooks."""
from __future__ import annotations

import os
import uuid
from typing import Optional

import requests
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="GooseStrike HackGPT Relay")


class PromptRequest(BaseModel):
    prompt: str
    context: Optional[dict] = None


class PromptResponse(BaseModel):
    request_id: str
    prompt: str
    echoed_context: Optional[dict]
    forwarded: bool
    recommendation: str


@app.post("/prompt", response_model=PromptResponse)
async def handle_prompt(body: PromptRequest) -> PromptResponse:
    request_id = str(uuid.uuid4())
    forwarded = False
    webhook = os.getenv("N8N_WEBHOOK_URL")
    if webhook:
        try:
            requests.post(
                webhook,
                json={"request_id": request_id, "prompt": body.prompt, "context": body.context},
                timeout=10,
            )
            forwarded = True
        except requests.RequestException:
            forwarded = False
    return PromptResponse(
        request_id=request_id,
        prompt=body.prompt,
        echoed_context=body.context,
        forwarded=forwarded,
        recommendation="HackGPT relay placeholder – plug in your model pipeline.",
    )


@app.get("/health")
async def health() -> dict:
    return {"ok": True}
