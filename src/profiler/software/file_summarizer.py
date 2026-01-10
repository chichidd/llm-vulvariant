"""文件摘要生成器 - 使用 LLM 分析文件"""

from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from llm import BaseLLMClient
from utils.logger import get_logger
from utils.llm_utils import parse_llm_json, extract_message_content
from profiler.profile_storage import ProfileStorageManager
from .prompts import CODE_SNIPPET_PROMPT

logger = get_logger(__name__)


class FileSummarizer:
    """并发地为文件生成摘要"""
    
    def __init__(
        self,
        llm_client: BaseLLMClient,
        max_workers: int = 4,

    ):
        self.llm_client = llm_client
        self.max_workers = max_workers

    def summarize_files(
        self,
        repo_path: Path,
        file_path_list: List[str],
        storage_manager: Optional[ProfileStorageManager] = None,
        repo_name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> Dict[str, Dict]:
        """
        并发地为文件生成摘要
        
        Args:
            file_path_list: 文件路径列表（相对路径）
            repo_path: 仓库根路径
            repo_name: 仓库名称
            version: 版本号
            
        Returns:
            {file_path: {summary_dict}}
        """
        if not file_path_list:
            return {}
        
        total_files = len(file_path_list)
        
        logger.info(f"Starting concurrent file summarization for {total_files} files "
                   f"(max_workers={self.max_workers})...")
        
        def analyze_single_file(file_path: str) -> tuple:
            """分析单个文件"""
            try:
                full_path = repo_path / file_path
                if not full_path.exists():
                    return file_path, None
                
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # 调用 LLM 生成摘要
                prompt = CODE_SNIPPET_PROMPT.format(
                    file_path=file_path,
                    file_content=content
                )

                response = self.llm_client.chat(
                    messages=[{"role": "user", "content": prompt}],
                )

                content = extract_message_content(response)
                summary = parse_llm_json(content)

                if storage_manager:
                    conversation_data = {
                        "step": "file_summary",
                        "file": file_path,
                        "prompt": prompt,
                        "response": content,
                        "parsed_summary": summary,
                    }
                    path_parts = (repo_name, version) if repo_name else ()
                    storage_manager.save_conversation(
                        "file_summary", conversation_data, *path_parts, file_identifier=file_path
                    )

                return file_path, summary
                
            except Exception as e:
                logger.debug(f"Failed to summarize {file_path}: {e}")
                return file_path, None
        
        # 并发处理
        summaries = {}
        completed = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(analyze_single_file, fp): fp 
                for fp in file_path_list
            }
            
            for future in as_completed(future_to_file):
                file_path, summary = future.result()
                if summary:
                    summaries[file_path] = summary
                
                completed += 1
                if completed % 10 == 0:
                    logger.info(f"Progress: {completed}/{total_files} files analyzed")
        
        logger.info(f"Completed file summarization: {len(summaries)}/{total_files} successful")
        return summaries
