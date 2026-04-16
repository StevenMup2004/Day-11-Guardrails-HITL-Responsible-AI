import json
from datetime import datetime
from google.adk.plugins import base_plugin


class AuditLogPlugin(base_plugin.BasePlugin):
    """Capture input/output events and export auditable JSON logs."""

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs = []
        self._pending_by_session = {}

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
                "metadata": metadata or {},
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
                "metadata": metadata or {},
            }
        )

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Record incoming user message and start-time marker."""
        session_id = None
        if invocation_context is not None:
            session_id = getattr(invocation_context, "session_id", None)

        user_text = self._extract_text(user_message)
        start_ts = datetime.utcnow()
        if session_id is not None:
            self._pending_by_session[session_id] = {
                "user_input": user_text,
                "start_ts": start_ts,
            }

        self.logs.append(
            {
                "timestamp": start_ts.isoformat() + "Z",
                "type": "input",
                "session_id": session_id,
                "user_input": user_text,
            }
        )

        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        """Record model output and computed latency without modifying response."""
        session_id = None
        if callback_context is not None:
            session_id = getattr(callback_context, "session_id", None)

        now = datetime.utcnow()
        response_text = self._extract_text(llm_response)

        pending = self._pending_by_session.pop(session_id, None)
        latency_ms = None
        user_input = ""
        if pending is not None:
            user_input = pending.get("user_input", "")
            start_ts = pending.get("start_ts", now)
            latency_ms = (now - start_ts).total_seconds() * 1000

        blocked_marker = any(
            marker in response_text.lower()
            for marker in ["request blocked", "i cannot provide", "i'm sorry, i can't"]
        )

        self.logs.append(
            {
                "timestamp": now.isoformat() + "Z",
                "type": "output",
                "session_id": session_id,
                "user_input": user_input,
                "response": response_text,
                "blocked": blocked_marker,
                "latency_ms": latency_ms,
            }
        )

        return llm_response

    def export_json(self, filepath="audit_log.json"):
        """Export logs to JSON in UTF-8 for report submission."""
        with open(filepath, "w") as f:
            json.dump(self.logs, f, indent=2, default=str)


class MonitoringAlert:
    """Compute safety metrics and print alerts when thresholds are exceeded."""

    def __init__(
        self,
        *,
        min_total_entries: int = 20,
        blocked_rate_threshold: float = 0.50,
        error_count_threshold: int = 1,
    ):
        self.min_total_entries = min_total_entries
        self.blocked_rate_threshold = blocked_rate_threshold
        self.error_count_threshold = error_count_threshold

    def _interaction_entries(self, logs: list) -> list:
        return [entry for entry in logs if entry.get("type") == "interaction"]

    def metrics(self, logs: list) -> dict:
        interactions = self._interaction_entries(logs)
        blocked_count = sum(1 for entry in interactions if entry.get("blocked"))
        error_count = sum(
            1
            for entry in interactions
            if "error:" in str(entry.get("response", "")).lower()
        )

        total_interactions = len(interactions)
        blocked_rate = (
            blocked_count / total_interactions if total_interactions else 0.0
        )
        return {
            "total_entries": len(logs),
            "total_interactions": total_interactions,
            "blocked_count": blocked_count,
            "blocked_rate": blocked_rate,
            "error_count": error_count,
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

        print("\n" + "=" * 70)
        print("AUDIT MONITORING SUMMARY")
        print("=" * 70)
        print(f"  Total log entries:     {metrics['total_entries']}")
        print(f"  Total interactions:    {metrics['total_interactions']}")
        print(f"  Blocked interactions:  {metrics['blocked_count']}")
        print(f"  Blocked rate:          {metrics['blocked_rate']:.0%}")
        print(f"  Error count:           {metrics['error_count']}")
        if alerts:
            print("  Alerts:")
            for alert in alerts:
                print(f"    - {alert}")
        else:
            print("  Alerts: none")
        print("=" * 70)

        return alerts