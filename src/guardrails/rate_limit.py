"""
Assignment 11 - Rate Limiter Guardrail

This module implements a per-user sliding-window limiter that blocks abusive
request bursts before they reach expensive model calls.
"""

import time
from collections import defaultdict, deque

from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users that exceed a request budget in a sliding time window.

    Why needed:
    - Stops abuse and brute-force prompting early.
    - Protects latency and token cost under high traffic.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows = defaultdict(deque)
        self._blocked_invocations = {}

        self.total_count = 0
        self.allowed_count = 0
        self.blocked_count = 0

    def _user_id(self, invocation_context: InvocationContext | None) -> str:
        """Return stable user id used for per-user throttling."""
        if invocation_context is None:
            return "anonymous"
        return getattr(invocation_context, "user_id", "anonymous")

    def _block_message(self, retry_after_seconds: int) -> str:
        """Create standardized block text with retry hint for clients/tests."""
        return (
            "[BLOCKED:RATE_LIMIT] Too many requests. "
            f"Try again in about {retry_after_seconds}s."
        )

    def _prune_window(self, user_window: deque, now_ts: float) -> None:
        """Drop expired request timestamps from the front of the deque."""
        while user_window and (now_ts - user_window[0]) > self.window_seconds:
            user_window.popleft()

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Apply per-user sliding-window check and mark invocation for blocking."""
        self.total_count += 1
        self._blocked_invocations.pop(invocation_context.invocation_id, None)

        user_id = self._user_id(invocation_context)
        now_ts = time.time()
        user_window = self.user_windows[user_id]
        self._prune_window(user_window, now_ts)

        if len(user_window) >= self.max_requests:
            self.blocked_count += 1
            oldest_ts = user_window[0]
            retry_after_seconds = max(1, int(self.window_seconds - (now_ts - oldest_ts)))
            self._blocked_invocations[invocation_context.invocation_id] = self._block_message(
                retry_after_seconds
            )
            return None

        user_window.append(now_ts)
        self.allowed_count += 1
        return None

    async def before_agent_callback(self, *, agent, callback_context):
        """Short-circuit the invocation when this plugin marked it as blocked."""
        block_message = self._blocked_invocations.pop(callback_context.invocation_id, None)
        if not block_message:
            return None

        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=block_message)],
        )

    def metrics(self) -> dict:
        """Expose counters for monitoring and assignment reporting."""
        return {
            "max_requests": self.max_requests,
            "window_seconds": self.window_seconds,
            "total_count": self.total_count,
            "allowed_count": self.allowed_count,
            "blocked_count": self.blocked_count,
            "blocked_rate": (self.blocked_count / self.total_count) if self.total_count else 0.0,
        }
