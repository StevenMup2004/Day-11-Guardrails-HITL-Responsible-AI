"""Audit logging and monitoring utilities for defense-in-depth pipeline."""

import json
from datetime import datetime

from google.adk.plugins import base_plugin


def _classify_block_layer(response_text: str) -> str:
    """Map standardized block prefixes to a reporting-friendly layer name."""
    if response_text.startswith("[BLOCKED:RATE_LIMIT]"):
        return "rate_limiter"
    if response_text.startswith("[BLOCKED:INPUT_INJECTION]"):
        return "input_guard_injection"
    if response_text.startswith("[BLOCKED:INPUT_TOPIC]"):
        return "input_guard_topic"
    if response_text.startswith("[BLOCKED:OUTPUT_JUDGE]"):
        return "output_judge"
    return "none"


class AuditLogPlugin(base_plugin.BasePlugin):
    """Capture input/output/interaction events and export auditable JSON logs.

    Why needed:
    - Supports incident analysis and assignment evidence artifacts.
    - Enables monitoring based on real interaction-level outcomes.
    """

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs = []
        self._pending_by_invocation = {}
        self._completed_invocations = set()

    def _extract_text(self, content) -> str:
        """Extract plain text from ADK content/response payloads."""
        if content is None:
            return ""

        # ADK model callbacks provide object with `.content`.
        if hasattr(content, "content") and content.content is not None:
            content = content.content

        parts = getattr(content, "parts", None)
        if not parts:
            return ""

        text_chunks = []
        for part in parts:
            part_text = getattr(part, "text", None)
            if part_text:
                text_chunks.append(part_text)
        return "".join(text_chunks)

    def record_interaction(
        self,
        *,
        source: str,
        user_input: str,
        response: str,
        blocked: bool,
        latency_ms: float | None = None,
        metadata: dict | None = None,
    ) -> None:
        """Record one interaction for non-plugin test flows."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        block_layer = _classify_block_layer(response)
        merged_metadata = {
            "block_layer": block_layer,
            **(metadata or {}),
        }

        self.logs.append(
            {
                "timestamp": timestamp,
                "type": "input",
                "source": source,
                "user_input": user_input,
            }
        )
        self.logs.append(
            {
                "timestamp": timestamp,
                "type": "output",
                "source": source,
                "response": response,
                "blocked": blocked,
                "latency_ms": latency_ms,
                "metadata": merged_metadata,
            }
        )
        self.logs.append(
            {
                "timestamp": timestamp,
                "type": "interaction",
                "source": source,
                "user_input": user_input,
                "response": response,
                "blocked": blocked,
                "latency_ms": latency_ms,
                "metadata": merged_metadata,
            }
        )

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Record incoming user message and start-time marker."""
        session_id = None
        user_id = "anonymous"
        invocation_id = None
        if invocation_context is not None:
            session_obj = getattr(invocation_context, "session", None)
            session_id = getattr(session_obj, "id", None)
            user_id = getattr(invocation_context, "user_id", "anonymous")
            invocation_id = getattr(invocation_context, "invocation_id", None)

        user_text = self._extract_text(user_message)
        start_ts = datetime.utcnow()
        if invocation_id is not None:
            self._pending_by_invocation[invocation_id] = {
                "session_id": session_id,
                "user_input": user_text,
                "user_id": user_id,
                "start_ts": start_ts,
            }
            self._completed_invocations.discard(invocation_id)

        self.logs.append(
            {
                "timestamp": start_ts.isoformat() + "Z",
                "type": "input",
                "invocation_id": invocation_id,
                "session_id": session_id,
                "user_id": user_id,
                "user_input": user_text,
            }
        )

        return None

    def _record_output_for_invocation(self, *, invocation_id: str, response_text: str) -> None:
        """Create output/interaction log entries exactly once per invocation."""
        if not invocation_id or invocation_id in self._completed_invocations:
            return

        now = datetime.utcnow()
        pending = self._pending_by_invocation.pop(invocation_id, None)
        self._completed_invocations.add(invocation_id)

        latency_ms = None
        session_id = None
        user_id = "anonymous"
        user_input = ""
        if pending is not None:
            session_id = pending.get("session_id")
            user_input = pending.get("user_input", "")
            user_id = pending.get("user_id", "anonymous")
            start_ts = pending.get("start_ts", now)
            latency_ms = (now - start_ts).total_seconds() * 1000

        block_layer = _classify_block_layer(response_text)
        blocked_marker = block_layer != "none"

        output_entry = {
            "timestamp": now.isoformat() + "Z",
            "type": "output",
            "invocation_id": invocation_id,
            "session_id": session_id,
            "user_id": user_id,
            "user_input": user_input,
            "response": response_text,
            "blocked": blocked_marker,
            "latency_ms": latency_ms,
            "metadata": {
                "block_layer": block_layer,
            },
        }
        self.logs.append(output_entry)

        self.logs.append(
            {
                "timestamp": now.isoformat() + "Z",
                "type": "interaction",
                "invocation_id": invocation_id,
                "session_id": session_id,
                "user_id": user_id,
                "user_input": user_input,
                "response": response_text,
                "blocked": blocked_marker,
                "latency_ms": latency_ms,
                "metadata": {
                    "block_layer": block_layer,
                },
            }
        )

    async def on_event_callback(self, *, invocation_context, event):
        """Capture final text response events, including short-circuited blocks."""
        if getattr(event, "author", "") == "user":
            return None
        if getattr(event, "partial", None) is True:
            return None
        if not event.is_final_response():
            return None

        response_text = self._extract_text(event)
        if not response_text:
            return None

        self._record_output_for_invocation(
            invocation_id=getattr(event, "invocation_id", ""),
            response_text=response_text,
        )
        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        """Fallback logger if final response was not captured by on_event_callback."""
        invocation_id = getattr(callback_context, "invocation_id", "") if callback_context else ""
        response_text = self._extract_text(llm_response)
        if response_text:
            self._record_output_for_invocation(
                invocation_id=invocation_id,
                response_text=response_text,
            )

        return llm_response

    def export_json(self, filepath="audit_log.json"):
        """Export logs to JSON in UTF-8 for report submission."""
        with open(filepath, "w", encoding="utf-8") as file_obj:
            json.dump(self.logs, file_obj, indent=2, default=str, ensure_ascii=False)


class MonitoringAlert:
    """Compute safety metrics and print alerts when thresholds are exceeded.

    Why needed:
    - Provides operational visibility for production safety posture.
    - Turns raw logs into measurable signals and threshold-based alerts.
    """

    def __init__(
        self,
        *,
        min_total_entries: int = 20,
        blocked_rate_threshold: float = 0.50,
        error_count_threshold: int = 1,
        judge_fail_rate_threshold: float = 0.30,
    ):
        self.min_total_entries = min_total_entries
        self.blocked_rate_threshold = blocked_rate_threshold
        self.error_count_threshold = error_count_threshold
        self.judge_fail_rate_threshold = judge_fail_rate_threshold

    def _interaction_entries(self, logs: list) -> list:
        """Return interaction-level logs for metric calculations."""
        return [entry for entry in logs if entry.get("type") == "interaction"]

    def metrics(self, logs: list) -> dict:
        """Aggregate assignment-required monitoring metrics from logs."""
        interactions = self._interaction_entries(logs)

        blocked_count = sum(1 for entry in interactions if entry.get("blocked"))
        error_count = sum(
            1
            for entry in interactions
            if "error:" in str(entry.get("response", "")).lower()
        )
        rate_limit_hits = sum(
            1
            for entry in interactions
            if entry.get("metadata", {}).get("block_layer") == "rate_limiter"
            or str(entry.get("response", "")).startswith("[BLOCKED:RATE_LIMIT]")
        )
        judge_fail_count = sum(
            1
            for entry in interactions
            if entry.get("metadata", {}).get("block_layer") == "output_judge"
            or str(entry.get("response", "")).startswith("[BLOCKED:OUTPUT_JUDGE]")
        )

        total_interactions = len(interactions)
        blocked_rate = (
            blocked_count / total_interactions if total_interactions else 0.0
        )
        judge_fail_rate = (
            judge_fail_count / total_interactions if total_interactions else 0.0
        )

        return {
            "total_entries": len(logs),
            "total_interactions": total_interactions,
            "blocked_count": blocked_count,
            "blocked_rate": blocked_rate,
            "error_count": error_count,
            "rate_limit_hits": rate_limit_hits,
            "judge_fail_count": judge_fail_count,
            "judge_fail_rate": judge_fail_rate,
        }

    def check_metrics(self, logs: list) -> list:
        """Return alert messages and print a compact monitoring summary."""
        metrics = self.metrics(logs)
        alerts = []

        if metrics["total_entries"] < self.min_total_entries:
            alerts.append(
                "ALERT: Audit entries below required minimum "
                f"({metrics['total_entries']} < {self.min_total_entries})"
            )

        if metrics["blocked_rate"] > self.blocked_rate_threshold:
            alerts.append(
                "ALERT: Blocked rate exceeded threshold "
                f"({metrics['blocked_rate']:.0%} > {self.blocked_rate_threshold:.0%})"
            )

        if metrics["error_count"] > self.error_count_threshold:
            alerts.append(
                "ALERT: Error count exceeded threshold "
                f"({metrics['error_count']} > {self.error_count_threshold})"
            )

        if metrics["judge_fail_rate"] > self.judge_fail_rate_threshold:
            alerts.append(
                "ALERT: Judge fail rate exceeded threshold "
                f"({metrics['judge_fail_rate']:.0%} > {self.judge_fail_rate_threshold:.0%})"
            )

        print("\n" + "=" * 70)
        print("AUDIT MONITORING SUMMARY")
        print("=" * 70)
        print(f"  Total log entries:     {metrics['total_entries']}")
        print(f"  Total interactions:    {metrics['total_interactions']}")
        print(f"  Blocked interactions:  {metrics['blocked_count']}")
        print(f"  Blocked rate:          {metrics['blocked_rate']:.0%}")
        print(f"  Rate-limit hits:       {metrics['rate_limit_hits']}")
        print(f"  Judge fail count:      {metrics['judge_fail_count']}")
        print(f"  Judge fail rate:       {metrics['judge_fail_rate']:.0%}")
        print(f"  Error count:           {metrics['error_count']}")
        if alerts:
            print("  Alerts:")
            for alert in alerts:
                print(f"    - {alert}")
        else:
            print("  Alerts: none")
        print("=" * 70)

        return alerts
