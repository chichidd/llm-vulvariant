"""Generic profile storage manager.

Provides a unified interface for saving and loading different kinds of profile data, including:
- Metadata (profile_info.json)
- Checkpoint data (checkpoints/)
- LLM conversation history (conversations/)
- Final results
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime
from utils.logger import get_logger

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
    
    def _ensure_dir(self, dir_path: Path) -> None:
        """Ensure the directory exists."""
        if dir_path:
            dir_path.mkdir(parents=True, exist_ok=True)
    
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
            try:
                with open(info_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load {info_filename}: {e}")
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
        
        self._ensure_dir(info_path.parent)
        try:
            with open(info_path, 'w', encoding='utf-8') as f:
                json.dump(profile_info, f, indent=2, ensure_ascii=False)
            logger.info(f"{self.profile_type} info saved: {info_path}")
        except Exception as e:
            logger.warning(f"Failed to save {info_filename}: {e}")
    
    # ==================== Checkpoint management ====================
    
    def get_checkpoint_dir(self, *path_parts: str) -> Optional[Path]:
        """Get the checkpoint directory."""
        profile_dir = self._get_profile_dir(*path_parts)
        if not profile_dir:
            return None
        
        checkpoint_dir = profile_dir / "checkpoints"
        self._ensure_dir(checkpoint_dir)
        return checkpoint_dir
    
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
        try:
            with open(checkpoint_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"Checkpoint saved: {checkpoint_path}")
        except Exception as e:
            logger.warning(f"Failed to save checkpoint {checkpoint_name}: {e}")
    
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
            try:
                with open(checkpoint_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                logger.info(f"Checkpoint loaded: {checkpoint_path}")
                return data
            except Exception as e:
                logger.warning(f"Failed to load checkpoint {checkpoint_name}: {e}")
        return None
    
    # ==================== LLM conversation management ====================
    
    def get_conversation_dir(self, conversation_type: str, *path_parts: str) -> Optional[Path]:
        """
        Get the conversation history directory.

        Args:
            conversation_type: Conversation type (e.g., 'source_features', 'basic_info').
            *path_parts: Path components.
        """
        profile_dir = self._get_profile_dir(*path_parts)
        if not profile_dir:
            return None
        
        conversation_dir = profile_dir / "conversations" / conversation_type
        self._ensure_dir(conversation_dir)
        return conversation_dir
    
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
            # Sanitize file identifier.
            safe_identifier = file_identifier.replace('/', '_').replace('\\', '_').replace(':', '_')
            filename = f"{safe_identifier}.json"
        else:
            filename = f"{conversation_type}.json"
        
        conversation_path = conversation_dir / filename
        
        try:
            with open(conversation_path, 'w', encoding='utf-8') as f:
                json.dump(conversation_data, f, indent=2, ensure_ascii=False)
            logger.debug(f"Conversation saved: {conversation_path}")
        except Exception as e:
            logger.warning(f"Failed to save conversation: {e}")
    
    def load_conversation(self, conversation_type: str, *path_parts: str) -> Optional[Dict[str, Any]]:
        """
        Load the latest conversation history (used to resume from checkpoints).

        Args:
            conversation_type: Conversation type (e.g., 'module_analysis').
            *path_parts: Path components.

        Returns:
            Conversation data dict, or None if it does not exist.
        """
        conversation_dir = self.get_conversation_dir(conversation_type, *path_parts)
        if not conversation_dir or not conversation_dir.exists():
            return None
        
        # Find all conversation files of this type (filenames no longer include a timestamp prefix).
        conversation_files = sorted(
            conversation_dir.glob(f"*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True  # Newest first.
        )
        
        if not conversation_files:
            return None
        
        # Load the latest conversation.
        latest_conversation = conversation_files[0]
        try:
            with open(latest_conversation, 'r', encoding='utf-8') as f:
                data = json.load(f)
            logger.info(f"Loaded conversation: {latest_conversation}")
            return data
        except Exception as e:
            logger.warning(f"Failed to load conversation from {latest_conversation}: {e}")
            return None
    
    # ==================== Final result management ====================
    
    def get_result_dir(self, *path_parts: str) -> Optional[Path]:
        """Get the result directory."""
        profile_dir = self._get_profile_dir(*path_parts)
        if profile_dir:
            self._ensure_dir(profile_dir)
        return profile_dir
    
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
        try:
            with open(result_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Final result saved: {result_path}")
        except Exception as e:
            logger.warning(f"Failed to save final result: {e}")
    
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
            try:
                with open(result_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"Failed to load final result: {e}")
        return None
