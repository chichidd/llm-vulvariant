"""Generic profile storage manager.

Provides a unified interface for saving and loading different kinds of profile data, including:
- Metadata (profile_info.json)
- Checkpoint data (checkpoints/)
- LLM conversation history (conversations/)
- Final results
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from utils.logger import get_logger
from utils.io_utils import read_json_file, write_atomic_json, write_atomic_text

logger = get_logger(__name__)


class ProfileStorageManager:
    """
    Generic profile storage manager.

    Manages saving and loading profile-related data. Supports:
    - Multi-level directory layout (e.g., repo/version/cve_id)
    - Saving and loading checkpoints
    - Saving LLM conversation history
    - Metadata management
    """
    
    def __init__(self, base_dir: Path, profile_type: str = "profile"):
        """
        Initialize the storage manager.

        Args:
            base_dir: Base storage directory (e.g., ~/vuln/profiles/soft or ~/vuln/profiles/vuln)
            profile_type: Profile type label used in log messages.
        """
        self.base_dir = Path(base_dir) if base_dir else None
        self.profile_type = profile_type
    
    def _get_profile_dir(self, *path_parts: str) -> Optional[Path]:
        """
        Get the profile directory path.

        Args:
            *path_parts: Path components (e.g., repo_name, commit, cve_id)

        Returns:
            The full directory path.
        """
        if not self.base_dir:
            return None
        
        profile_dir = self.base_dir
        for part in path_parts:
            if part:  # Skip empty strings
                profile_dir = profile_dir / part
        
        return profile_dir
    
    def _read_json(self, path: Path) -> Optional[Any]:
        """Read JSON file content."""
        try:
            return read_json_file(path)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(f"Failed to read JSON file {path}: {exc}")
            return None

    def _write_json(self, path: Path, data: Any) -> bool:
        """Write JSON data."""
        try:
            write_atomic_json(path, data)
            return True
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(f"Failed to write JSON file {path}: {exc}")
            return False

    def _read_text(self, path: Path) -> Optional[str]:
        """Read text file content."""
        try:
            return path.read_text(encoding="utf-8")
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(f"Failed to read text file {path}: {exc}")
            return None

    def _write_text(self, path: Path, content: str) -> bool:
        """Write text file content."""
        try:
            write_atomic_text(path, content)
            return True
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(f"Failed to write text file {path}: {exc}")
            return False
    
    # ==================== Metadata management ====================
    
    def get_profile_info_path(self, *path_parts: str, info_filename: str = "profile_info.json") -> Optional[Path]:
        """
        Get the path to profile_info.json.

        Args:
            *path_parts: Path components.
            info_filename: Metadata file name.
        """
        profile_dir = self._get_profile_dir(*path_parts)
        return profile_dir / info_filename if profile_dir else None
    
    def load_profile_info(self, *path_parts: str, info_filename: str = "profile_info.json") -> Optional[Dict[str, Any]]:
        """
        Load profile metadata.

        Args:
            *path_parts: Path components.
            info_filename: Metadata file name.
        """
        info_path = self.get_profile_info_path(*path_parts, info_filename=info_filename)
        if info_path and info_path.exists():
            data = self._read_json(info_path)
            if data is not None:
                return data
        return None
    
    def save_profile_info(self, profile_info: Dict[str, Any], *path_parts: str, info_filename: str = "profile_info.json") -> None:
        """
        Save profile metadata.

        Args:
            profile_info: Metadata to save.
            *path_parts: Path components.
            info_filename: Metadata file name.
        """
        info_path = self.get_profile_info_path(*path_parts, info_filename=info_filename)
        if not info_path:
            return

        if self._write_json(info_path, profile_info):
            logger.info(f"{self.profile_type} info saved: {info_path}")
    
    # ==================== Checkpoint management ====================
    
    def get_checkpoint_dir(self, *path_parts: str) -> Optional[Path]:
        """Get the checkpoint directory path."""
        profile_dir = self._get_profile_dir(*path_parts)
        if not profile_dir:
            return None
        return profile_dir / "checkpoints"
    
    def save_checkpoint(self, checkpoint_name: str, data: Dict[str, Any], *path_parts: str) -> None:
        """
        Save checkpoint data.

        Args:
            checkpoint_name: Checkpoint name (e.g., 'source_features', 'repo_info').
            data: Data to save.
            *path_parts: Path components.
        """
        checkpoint_dir = self.get_checkpoint_dir(*path_parts)
        if not checkpoint_dir:
            return
        
        checkpoint_path = checkpoint_dir / f"{checkpoint_name}.json"
        if self._write_json(checkpoint_path, data):
            logger.info(f"Checkpoint saved: {checkpoint_path}")
    
    def load_checkpoint(self, checkpoint_name: str, *path_parts: str) -> Optional[Dict[str, Any]]:
        """
        Load checkpoint data.

        Args:
            checkpoint_name: Checkpoint name.
            *path_parts: Path components.
        """
        checkpoint_dir = self.get_checkpoint_dir(*path_parts)
        if not checkpoint_dir:
            return None
        
        checkpoint_path = checkpoint_dir / f"{checkpoint_name}.json"
        if checkpoint_path.exists():
            data = self._read_json(checkpoint_path)
            if data is not None:
                logger.info(f"Checkpoint loaded: {checkpoint_path}")
            return data
        return None
    
    # ==================== LLM conversation management ====================
    
    def get_conversation_dir(self, conversation_type: str, *path_parts: str) -> Optional[Path]:
        """
        Get the conversation history directory path.

        Args:
            conversation_type: Conversation type (e.g., 'source_features', 'basic_info').
            *path_parts: Path components.
        """
        profile_dir = self._get_profile_dir(*path_parts)
        if not profile_dir:
            return None
        return profile_dir / "conversations" / conversation_type
    
    def save_conversation(
        self, 
        conversation_type: str, 
        conversation_data: Dict[str, Any], 
        *path_parts: str,
        file_identifier: str = None
    ) -> None:
        """
        Save LLM conversation history.

        Args:
            conversation_type: Conversation type (e.g., 'source_features').
            conversation_data: Conversation data containing prompt/response, etc.
            *path_parts: Path components.
            file_identifier: Optional file identifier used to distinguish multiple conversations of the same type.
        """
        conversation_dir = self.get_conversation_dir(conversation_type, *path_parts)
        if not conversation_dir:
            return
        
        # Build filename (no longer includes a timestamp).
        if file_identifier:
            safe_identifier = self._sanitize_file_identifier(file_identifier)
            filename = f"{safe_identifier}.json"
        else:
            filename = f"{conversation_type}.json"
        
        conversation_path = conversation_dir / filename
        
        if self._write_json(conversation_path, conversation_data):
            logger.debug(f"Conversation saved: {conversation_path}")
    
    def load_conversation(
        self,
        conversation_type: str,
        *path_parts: str,
        file_identifier: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Load the latest conversation history (used to resume from checkpoints).

        Args:
            conversation_type: Conversation type (e.g., 'module_analysis').
            *path_parts: Path components.
            file_identifier: Optional exact conversation identifier.

        Returns:
            Conversation data dict, or None if it does not exist.
        """
        conversation_dir = self.get_conversation_dir(conversation_type, *path_parts)
        if not conversation_dir or not conversation_dir.exists():
            return None

        if file_identifier:
            conversation_path = conversation_dir / f"{self._sanitize_file_identifier(file_identifier)}.json"
            if not conversation_path.exists():
                return None
            data = self._read_json(conversation_path)
            if data is not None:
                logger.info(f"Loaded conversation: {conversation_path}")
            return data
        
        # Find all conversation files of this type (filenames no longer include a timestamp prefix).
        conversation_files = sorted(
            conversation_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime_ns,
            reverse=True  # Newest first.
        )
        
        if not conversation_files:
            return None
        
        # Load the latest conversation.
        latest_conversation = conversation_files[0]
        data = self._read_json(latest_conversation)
        if data is not None:
            logger.info(f"Loaded conversation: {latest_conversation}")
        return data
    
    # ==================== Final result management ====================
    
    def get_result_dir(self, *path_parts: str) -> Optional[Path]:
        """Get the result directory path."""
        return self._get_profile_dir(*path_parts)
    
    def save_final_result(self, filename: str, content: str, *path_parts: str) -> None:
        """
        Save the final result.

        Args:
            filename: File name (e.g., 'software_profile.json').
            content: File contents.
            *path_parts: Path components.
        """
        result_dir = self.get_result_dir(*path_parts)
        if not result_dir:
            return
        
        result_path = result_dir / filename
        if self._write_text(result_path, content):
            logger.info(f"Final result saved: {result_path}")
    
    def load_final_result(self, filename: str, *path_parts: str) -> Optional[str]:
        """
        Load the final result.

        Args:
            filename: File name.
            *path_parts: Path components.
        """
        result_dir = self.get_result_dir(*path_parts)
        if not result_dir:
            return None
        
        result_path = result_dir / filename
        if result_path.exists():
            return self._read_text(result_path)
        return None
    @staticmethod
    def _sanitize_file_identifier(file_identifier: str) -> str:
        """Normalize conversation identifiers so they map to safe filenames."""
        return file_identifier.replace('/', '_').replace('\\', '_').replace(':', '_')
