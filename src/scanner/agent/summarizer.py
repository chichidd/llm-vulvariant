"""Conversation compression helpers.

This module now delegates to utils.agent_conversation to keep a single source
of truth for compression logic.
"""

from utils.agent_conversation import compress_iteration_conversation

__all__ = ["compress_iteration_conversation"]
