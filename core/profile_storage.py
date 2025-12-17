"""
通用的Profile存储管理器

提供统一的接口用于保存和加载各种profile数据，包括：
- 元数据 (profile_info.json)
- 检查点数据 (checkpoints/)
- LLM对话历史 (conversations/)
- 最终结果
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime


class ProfileStorageManager:
    """
    通用的Profile存储管理器
    
    用于管理profile相关数据的保存和加载，支持：
    - 多级目录结构 (如 repo/version/cve_id)
    - 检查点保存与加载
    - LLM对话历史保存
    - 元数据管理
    """
    
    def __init__(self, base_dir: Path, profile_type: str = "profile"):
        """
        初始化存储管理器
        
        Args:
            base_dir: 基础存储目录 (如 repo-profiles/ 或 vuln-profiles/)
            profile_type: profile类型标识，用于日志输出
        """
        self.base_dir = Path(base_dir) if base_dir else None
        self.profile_type = profile_type
    
    def _get_profile_dir(self, *path_parts: str) -> Optional[Path]:
        """
        获取profile目录路径
        
        Args:
            *path_parts: 路径组成部分 (如 repo_name, commit, cve_id)
            
        Returns:
            完整的目录路径
        """
        if not self.base_dir:
            return None
        
        profile_dir = self.base_dir
        for part in path_parts:
            if part:  # 跳过空字符串
                profile_dir = profile_dir / part
        
        return profile_dir
    
    def _ensure_dir(self, dir_path: Path) -> None:
        """确保目录存在"""
        if dir_path:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    # ==================== 元数据管理 ====================
    
    def get_profile_info_path(self, *path_parts: str, info_filename: str = "profile_info.json") -> Optional[Path]:
        """
        获取profile_info.json的路径
        
        Args:
            *path_parts: 路径组成部分
            info_filename: 元数据文件名
        """
        profile_dir = self._get_profile_dir(*path_parts)
        return profile_dir / info_filename if profile_dir else None
    
    def load_profile_info(self, *path_parts: str, info_filename: str = "profile_info.json") -> Optional[Dict[str, Any]]:
        """
        加载profile元数据
        
        Args:
            *path_parts: 路径组成部分
            info_filename: 元数据文件名
        """
        info_path = self.get_profile_info_path(*path_parts, info_filename=info_filename)
        if info_path and info_path.exists():
            try:
                with open(info_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[WARN] Failed to load {info_filename}: {e}")
        return None
    
    def save_profile_info(self, profile_info: Dict[str, Any], *path_parts: str, info_filename: str = "profile_info.json") -> None:
        """
        保存profile元数据
        
        Args:
            profile_info: 要保存的元数据
            *path_parts: 路径组成部分
            info_filename: 元数据文件名
        """
        info_path = self.get_profile_info_path(*path_parts, info_filename=info_filename)
        if not info_path:
            return
        
        self._ensure_dir(info_path.parent)
        try:
            with open(info_path, 'w', encoding='utf-8') as f:
                json.dump(profile_info, f, indent=2, ensure_ascii=False)
            print(f"[INFO] {self.profile_type} info saved: {info_path}")
        except Exception as e:
            print(f"[WARN] Failed to save {info_filename}: {e}")
    
    # ==================== 检查点管理 ====================
    
    def get_checkpoint_dir(self, *path_parts: str) -> Optional[Path]:
        """获取检查点目录"""
        profile_dir = self._get_profile_dir(*path_parts)
        if not profile_dir:
            return None
        
        checkpoint_dir = profile_dir / "checkpoints"
        self._ensure_dir(checkpoint_dir)
        return checkpoint_dir
    
    def save_checkpoint(self, checkpoint_name: str, data: Dict[str, Any], *path_parts: str) -> None:
        """
        保存检查点数据
        
        Args:
            checkpoint_name: 检查点名称 (如 'source_features', 'repo_info')
            data: 要保存的数据
            *path_parts: 路径组成部分
        """
        checkpoint_dir = self.get_checkpoint_dir(*path_parts)
        if not checkpoint_dir:
            return
        
        checkpoint_path = checkpoint_dir / f"{checkpoint_name}.json"
        try:
            with open(checkpoint_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"[INFO] Checkpoint saved: {checkpoint_path}")
        except Exception as e:
            print(f"[WARN] Failed to save checkpoint {checkpoint_name}: {e}")
    
    def load_checkpoint(self, checkpoint_name: str, *path_parts: str) -> Optional[Dict[str, Any]]:
        """
        加载检查点数据
        
        Args:
            checkpoint_name: 检查点名称
            *path_parts: 路径组成部分
        """
        checkpoint_dir = self.get_checkpoint_dir(*path_parts)
        if not checkpoint_dir:
            return None
        
        checkpoint_path = checkpoint_dir / f"{checkpoint_name}.json"
        if checkpoint_path.exists():
            try:
                with open(checkpoint_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                print(f"[INFO] Checkpoint loaded: {checkpoint_path}")
                return data
            except Exception as e:
                print(f"[WARN] Failed to load checkpoint {checkpoint_name}: {e}")
        return None
    
    # ==================== LLM对话管理 ====================
    
    def get_conversation_dir(self, conversation_type: str, *path_parts: str) -> Optional[Path]:
        """
        获取对话历史目录
        
        Args:
            conversation_type: 对话类型 (如 'source_features', 'basic_info')
            *path_parts: 路径组成部分
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
        保存LLM对话历史
        
        Args:
            conversation_type: 对话类型 (如 'source_features')
            conversation_data: 对话数据，包含prompt、response等
            *path_parts: 路径组成部分
            file_identifier: 文件标识符 (可选，用于区分同类型的不同对话)
        """
        conversation_dir = self.get_conversation_dir(conversation_type, *path_parts)
        if not conversation_dir:
            return
        
        # 生成时间戳
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]  # 精确到毫秒
        
        # 构建文件名
        if file_identifier:
            # 清理文件标识符
            safe_identifier = file_identifier.replace('/', '_').replace('\\', '_').replace(':', '_')
            filename = f"{timestamp}_{conversation_type}_{safe_identifier}.json"
        else:
            filename = f"{timestamp}_{conversation_type}.json"
        
        conversation_path = conversation_dir / filename
        
        try:
            with open(conversation_path, 'w', encoding='utf-8') as f:
                json.dump(conversation_data, f, indent=2, ensure_ascii=False)
            print(f"[DEBUG] Conversation saved: {conversation_path}")
        except Exception as e:
            print(f"[WARN] Failed to save conversation: {e}")
    
    # ==================== 最终结果管理 ====================
    
    def get_result_dir(self, *path_parts: str) -> Optional[Path]:
        """获取结果目录"""
        profile_dir = self._get_profile_dir(*path_parts)
        if profile_dir:
            self._ensure_dir(profile_dir)
        return profile_dir
    
    def save_final_result(self, filename: str, content: str, *path_parts: str) -> None:
        """
        保存最终结果
        
        Args:
            filename: 文件名 (如 'software_profile.json')
            content: 文件内容
            *path_parts: 路径组成部分
        """
        result_dir = self.get_result_dir(*path_parts)
        if not result_dir:
            return
        
        result_path = result_dir / filename
        try:
            with open(result_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"[INFO] Final result saved: {result_path}")
        except Exception as e:
            print(f"[WARN] Failed to save final result: {e}")
    
    def load_final_result(self, filename: str, *path_parts: str) -> Optional[str]:
        """
        加载最终结果
        
        Args:
            filename: 文件名
            *path_parts: 路径组成部分
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
                print(f"[WARN] Failed to load final result: {e}")
        return None
