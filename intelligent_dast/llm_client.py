"""LLM client for the Intelligent DAST steering loop.

Supports two providers:
  - "anthropic" — Anthropic SDK (claude-sonnet-4-5, default)
  - "ollama"    — local Ollama instance (any model name from config)

Each flow gets its own session_id so conversation histories stay isolated.
"""

from __future__ import annotations

import os
import logging
from typing import Dict, List, Optional

try:
    import anthropic as anthropic_sdk
except ImportError:
    anthropic_sdk = None  # type: ignore

try:
    from ollama import Client as OllamaClient
except ImportError:
    OllamaClient = None  # type: ignore

logger = logging.getLogger(__name__)

_DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5-20241022"
_DEFAULT_OLLAMA_MODEL = "llama3"
_MAX_TOKENS = 1024
_TEMPERATURE = 0.2


class LLMClient:
    """Multi-provider LLM client with per-session conversation history.

    Args:
        provider:        "anthropic" or "ollama".
        model:           Model name override. Falls back to provider default.
        api_key:         Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
                         Ignored for ollama.
        ollama_base_url: Ollama server URL. Defaults to http://localhost:11434.
    """

    def __init__(
        self,
        provider: str = "anthropic",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        ollama_base_url: str = "http://localhost:11434",
    ) -> None:
        self._provider = provider
        self._sessions: Dict[str, List[Dict[str, str]]] = {}

        if provider == "anthropic":
            if anthropic_sdk is None:
                raise RuntimeError(
                    "anthropic package is required for provider='anthropic'. "
                    "Run: pip install anthropic"
                )
            resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
            if not resolved_key:
                raise RuntimeError(
                    "No API key provided and ANTHROPIC_API_KEY env var is not set"
                )
            self._anthropic_client = anthropic_sdk.Anthropic(api_key=resolved_key)
            self._ollama_client = None
            self._model = model or _DEFAULT_ANTHROPIC_MODEL

        elif provider == "ollama":
            if OllamaClient is None:
                raise RuntimeError(
                    "ollama package is required for provider='ollama'. "
                    "Run: pip install ollama"
                )
            self._anthropic_client = None
            self._ollama_client = OllamaClient(host=ollama_base_url)
            self._model = model or _DEFAULT_OLLAMA_MODEL

        else:
            raise RuntimeError(
                f"Unknown provider: {provider!r}. Use 'anthropic' or 'ollama'"
            )

        logger.info(f"[llm_client] Initialized: provider={provider} model={self._model}")

    def new_session(self, session_id: str) -> None:
        """Clear conversation history for a session."""
        self._sessions[session_id] = []
        logger.debug(f"[llm_client] New session: {session_id}")

    def get_history(self, session_id: str) -> List[Dict[str, str]]:
        """Return the conversation history for a session (copy)."""
        return list(self._sessions.get(session_id, []))

    def chat(self, session_id: str, system: str, message: str) -> str:
        """Send a message within a session and return the assistant's response.

        Appends the user message to the session history, calls the API with
        the full history, appends the assistant response, and returns its text.

        Args:
            session_id: Identifies the conversation thread (typically flow_id).
            system:     System prompt for this call.
            message:    User message content.

        Returns:
            The assistant's response text.
        """
        if session_id not in self._sessions:
            self._sessions[session_id] = []

        history = self._sessions[session_id]
        history.append({"role": "user", "content": message})

        logger.debug(
            f"[llm_client] session={session_id} turns={len(history)} "
            f"msg_len={len(message)}"
        )

        if self._provider == "anthropic":
            assistant_text = self._chat_anthropic(system, history)
        else:
            assistant_text = self._chat_ollama(system, history)

        history.append({"role": "assistant", "content": assistant_text})
        return assistant_text

    # ------------------------------------------------------------------
    # Provider implementations
    # ------------------------------------------------------------------

    def _chat_anthropic(self, system: str, messages: List[Dict[str, str]]) -> str:
        """Call Anthropic Messages API."""
        response = self._anthropic_client.messages.create(
            model=self._model,
            max_tokens=_MAX_TOKENS,
            temperature=_TEMPERATURE,
            system=system,
            messages=messages,
        )
        return response.content[0].text

    def _chat_ollama(self, system: str, messages: List[Dict[str, str]]) -> str:
        """Call Ollama chat API. System prompt is prepended as a system message."""
        ollama_messages = [{"role": "system", "content": system}] + messages
        response = self._ollama_client.chat(
            model=self._model,
            messages=ollama_messages,
        )
        return response.message.content
