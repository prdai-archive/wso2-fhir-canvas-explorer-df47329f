from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from typing import Any

from apip_sdk_core import (
    BodyProcessingMode,
    DownstreamResponseModifications,
    ExecutionContext,
    ImmediateResponse,
    ProcessingMode,
    RequestAction,
    RequestContext,
    RequestPolicy,
    ResponseAction,
    ResponseContext,
    ResponsePolicy,
    UpstreamRequestModifications,
)
MODEL_NAME = "OpenMed/OpenMed-PII-SuperClinical-Small-44M-v1"
SKIP_KEYS = {"model", "role", "type", "name", "tool_call_id", "id"}

logger = logging.getLogger("pii-masking-openmed")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_handler)
logger.propagate = False


def _message_contents(payload: Any) -> str:
    """The chat messages' text, without the JSON noise."""
    try:
        return " ".join(str(m["content"]) for m in payload["messages"])
    except (TypeError, KeyError):
        return json.dumps(payload)


def _reply_contents(body: bytes) -> str:
    """The assistant reply text out of a chat-completion response."""
    try:
        payload = json.loads(body)
        return " ".join(str(c["message"]["content"]) for c in payload["choices"])
    except (ValueError, TypeError, KeyError):
        return body.decode("utf-8", errors="replace")


class PiiMaskingOpenmedPolicy(RequestPolicy, ResponsePolicy):
    """Redact PII on the way to the LLM and restore it on the way back, in-process.

    Request phase: every free-text string in the buffered body is redacted with
    openmed's privacy gateway — each entity becomes a delimited placeholder
    (``<<OPENMED_PHI_NAME_..._000001>>``) and the placeholder -> original-value
    mapping is kept in memory. Response phase: the validating reidentifier
    swaps the placeholders the LLM echoed back for the real values — and
    rejects hallucinated or mangled ones, in which case the still-redacted
    response is passed through unchanged.
    """

    def __init__(self) -> None:
        self._mappings: dict[str, dict[str, str]] = {}

    def mode(self) -> ProcessingMode:
        return ProcessingMode(
            request_body_mode=BodyProcessingMode.BUFFER,
            response_body_mode=BodyProcessingMode.BUFFER,
        )

    def _redact_text(self, text_blob: str, mapping: dict[str, str]) -> str:
        if not text_blob.strip():
            return text_blob
        from openmed import extract_pii
        from openmed.service.privacy_gateway import coerce_gateway_entities, redact_text

        entities = coerce_gateway_entities(extract_pii(text_blob, model_name=MODEL_NAME), text_blob)
        session = redact_text(text_blob, entities, request_id=uuid.uuid4().hex)
        mapping.update(session.placeholder_map)
        return session.redacted_text

    def _redact_structure(self, node: Any, mapping: dict[str, str]) -> Any:
        if isinstance(node, dict):
            return {k: (v if k in SKIP_KEYS else self._redact_structure(v, mapping)) for k, v in node.items()}
        if isinstance(node, list):
            return [self._redact_structure(item, mapping) for item in node]
        if isinstance(node, str):
            return self._redact_text(node, mapping)
        return node

    def on_request_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: RequestContext,
        params: dict[str, Any],
    ) -> RequestAction:
        if ctx.body is None or not ctx.body.present or ctx.body.content is None:
            return None

        try:
            payload = json.loads(ctx.body.content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.info("RECEIVED FROM CLIENT: (non-JSON body, rejected)")
            return ImmediateResponse(
                status_code=400,
                body=b'{"error": "request body must be JSON"}',
                headers={"content-type": "application/json"},
            )

        logger.info("RECEIVED FROM CLIENT: %s", _message_contents(payload))
        mapping: dict[str, str] = {}
        try:
            redacted = self._redact_structure(payload, mapping)
        except Exception:
            # Fail closed: never forward a payload we could not redact cleanly.
            logger.exception("PII redaction failed")
            return ImmediateResponse(
                status_code=502,
                body=b'{"error": "PII redaction failed"}',
                headers={"content-type": "application/json"},
            )

        masked = json.dumps(redacted).encode()
        if mapping:
            self._mappings[ctx.shared.request_id] = mapping
        logger.info("SENT TO OPENAI: %s", _message_contents(redacted))
        return UpstreamRequestModifications(
            body=masked,
            headers_to_set={"content-length": str(len(masked))},
        )

    def on_response_body(
        self,
        execution_ctx: ExecutionContext,
        ctx: ResponseContext,
        params: dict[str, Any],
    ) -> ResponseAction:
        mapping = self._mappings.pop(ctx.shared.request_id, None)
        if not mapping or ctx.response_body is None or not ctx.response_body.present:
            return None
        if ctx.response_body.content is None:
            return None

        from openmed.service.privacy_gateway import PrivacyReidentificationError, reidentify_placeholders

        text = ctx.response_body.content.decode("utf-8", errors="replace")
        logger.info("RECEIVED FROM OPENAI: %s", _reply_contents(ctx.response_body.content))
        try:
            restored = reidentify_placeholders(text, mapping).encode()
        except PrivacyReidentificationError:
            # The LLM hallucinated or mangled a placeholder; passing the still-redacted response through leaks nothing.
            logger.warning("response %s: reidentification rejected, leaving redacted", ctx.shared.request_id)
            return None

        logger.info("RETURNED TO CLIENT: %s", _reply_contents(restored))
        return DownstreamResponseModifications(
            body=restored,
            headers_to_set={"content-length": str(len(restored))},
        )


def get_policy(metadata, params):
    return PiiMaskingOpenmedPolicy()


def _warm_up_model() -> None:
    try:
        started = time.perf_counter()
        from openmed import extract_pii

        extract_pii("warm up", model_name=MODEL_NAME)
        logger.info("OpenMed model loaded in %.1f s", time.perf_counter() - started)
    except Exception:
        logger.exception("model warm-up failed; the first request will load the model instead")


# The policy engine imports this module at startup, so this warms the model before traffic arrives.
threading.Thread(target=_warm_up_model, name="openmed-warmup", daemon=True).start()
