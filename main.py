import os
import json
import hashlib
import hmac
from typing import Any, Dict, Optional

import requests
from fastapi import FastAPI, Header, HTTPException, Request, Query
from fastapi.responses import JSONResponse

app = FastAPI(title="REAL Instagram Intelligence Agent")

PIPEDRIVE_API_TOKEN = os.getenv("PIPEDRIVE_API_TOKEN", "")
PIPEDRIVE_PERSONS_V1_URL = os.getenv("PIPEDRIVE_PERSONS_V1_URL", "https://api.pipedrive.com/v1/persons")
PIPEDRIVE_LEADS_V1_URL = os.getenv("PIPEDRIVE_LEADS_V1_URL", "https://api.pipedrive.com/v1/leads")
PIPEDRIVE_NOTES_V1_URL = os.getenv("PIPEDRIVE_NOTES_V1_URL", "https://api.pipedrive.com/v1/notes")

META_VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "")
META_APP_SECRET = os.getenv("META_APP_SECRET", "")


def pipedrive_params() -> Dict[str, str]:
    if not PIPEDRIVE_API_TOKEN:
        raise HTTPException(status_code=500, detail="Missing PIPEDRIVE_API_TOKEN")
    return {"api_token": PIPEDRIVE_API_TOKEN}


def verify_meta_signature(payload: bytes, signature_256: Optional[str]) -> bool:
    if not META_APP_SECRET:
        return True
    if not signature_256:
        return False
    expected = "sha256=" + hmac.new(
        META_APP_SECRET.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_256)


def search_person_by_name(name: str) -> Optional[int]:
    url = f"{PIPEDRIVE_PERSONS_V1_URL}/search"
    resp = requests.get(
        url,
        params={**pipedrive_params(), "term": name, "exact_match": False},
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})
    items = data.get("items") or []
    if not items:
        return None
    first = items[0].get("item", {})
    return first.get("id")


def create_person(name: str) -> int:
    payload: Dict[str, Any] = {"name": name}
    resp = requests.post(
        PIPEDRIVE_PERSONS_V1_URL,
        params=pipedrive_params(),
        json=payload,
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json()["data"]["id"]


def get_or_create_person(name: str) -> int:
    existing_id = search_person_by_name(name)
    if existing_id:
        return existing_id
    return create_person(name)


def create_lead(title: str, person_id: int, source: str) -> str:
    payload: Dict[str, Any] = {
        "title": title,
        "person_id": person_id,
        "source_name": source,
    }
    resp = requests.post(
        PIPEDRIVE_LEADS_V1_URL,
        params=pipedrive_params(),
        json=payload,
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json()["data"]["id"]


def add_note(content: str, person_id: Optional[int] = None, lead_id: Optional[str] = None) -> int:
    payload: Dict[str, Any] = {"content": content}
    if person_id:
        payload["person_id"] = person_id
    if lead_id:
        payload["lead_id"] = lead_id
    resp = requests.post(
        PIPEDRIVE_NOTES_V1_URL,
        params=pipedrive_params(),
        json=payload,
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json()["data"]["id"]


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/webhooks/meta")
def verify_meta_webhook(
    hub_mode: str = Query(..., alias="hub.mode"),
    hub_verify_token: str = Query(..., alias="hub.verify_token"),
    hub_challenge: str = Query(..., alias="hub.challenge"),
):
    if hub_mode == "subscribe" and hub_verify_token == META_VERIFY_TOKEN:
        return JSONResponse(content=int(hub_challenge))
    raise HTTPException(status_code=403, detail="Meta webhook verification failed")


@app.post("/webhooks/meta")
async def receive_meta_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(default=None),
):
    body = await request.body()
    if not verify_meta_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=403, detail="Invalid Meta signature")

    payload = await request.json()

    for entry in payload.get("entry", []):
        for messaging in entry.get("messaging", []):
            message = messaging.get("message", {})
            sender = messaging.get("sender", {})
            if not message or sender.get("id") is None:
                continue

            message_text = message.get("text") or "[non-text message received]"
            sender_id = str(sender.get("id"))
            person_name = f"Instagram {sender_id}"

            person_id = get_or_create_person(person_name)
            lead_id = create_lead(
                title=f"Instagram inbound - {person_name}",
                person_id=person_id,
                source="Instagram",
            )

            note_lines = [
                "Source: Instagram",
                f"Sender ID: {sender_id}",
                "",
                "Inbound message:",
                message_text,
                "",
                "Raw payload:",
                json.dumps(payload, indent=2),
            ]
            add_note("\n".join(note_lines), person_id=person_id, lead_id=lead_id)

    return {"received": True}
