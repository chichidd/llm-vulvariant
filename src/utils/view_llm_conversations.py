#!/usr/bin/env python3
"""
### 对话历史存储目录
```
{output_dir}/
  {repo_name}/
    {version}/
      ├── checkpoints/
      │   ├── repo_info.json
      │   ├── basic_info.json
      │   ├── file_summaries.json
      │   └── modules.json
      ├── conversations/                    # 新增目录
      │   ├── 20251211_143025_123_basic_info.json
      │   ├── 20251211_143026_456_file_summary_main.py.json
      │   ├── 20251211_143027_789_file_summary_utils.py.json
      │   ├── 20251211_143030_012_module_analysis_iter_01.json
      │   ├── 20251211_143031_345_module_analysis_iter_02.json
      │   ├── 20251211_143032_678_module_analysis_iter_03.json
      │   └── 20251211_143040_901_module_analysis_fallback.json
      └── software_profile.json
    profile_info.json
```


查看和分析LLM对话历史的工具脚本
**功能:**
1. **list**: 列出所有对话文件并按步骤分类统计
2. **summary**: 显示对话摘要（前10个）
3. **view**: 查看特定对话的详细内容
4. **iterations**: 分析模块分析的迭代过程

**使用示例:**
```bash
# 列出所有对话
python view_llm_conversations.py output_dir/NeMo/abc123/conversations

# 显示摘要
python view_llm_conversations.py output_dir/NeMo/abc123/conversations summary

# 查看特定对话
python view_llm_conversations.py output_dir/NeMo/abc123/conversations view 20251211_143025_123_basic_info.json

# 分析迭代过程
python view_llm_conversations.py output_dir/NeMo/abc123/conversations iterations
```

### 简单查看
```bash
# 列出所有对话
ls -lh output_dir/NeMo/{version}/conversations/

# 查看最新的对话
ls -lt output_dir/NeMo/{version}/conversations/ | head

# 查看特定类型的对话
ls output_dir/NeMo/{version}/conversations/*module_analysis*
```

### JSON格式化查看
```bash
# 使用jq格式化查看
cat conversations/20251211_143025_123_basic_info.json | jq .

# 只查看prompt
cat conversations/20251211_143025_123_basic_info.json | jq .prompt

# 只查看响应
cat conversations/20251211_143025_123_basic_info.json | jq .response
```


```bash
# 找出分析失败的文件
grep -l "Failed to parse" conversations/*file_summary*.json

# 查看失败的响应
cat conversations/20251211_143026_456_file_summary_problematic.py.json | jq .response
```


# 删除7天前的对话
find profiles/NeMo/*/conversations -name "*.json" -mtime +7 -delete


"""

### Python脚本分析
# ```python
# import json
# from pathlib import Path

# # 加载对话历史
# conversation_dir = Path("output_dir/NeMo/{version}/conversations")

# # 统计对话数量
# conversations = list(conversation_dir.glob("*.json"))
# print(f"Total conversations: {len(conversations)}")

# # 按类型分类
# from collections import Counter
# steps = [c.stem.split('_')[3] for c in conversations]
# print(Counter(steps))

# # 读取特定对话
# with open(conversations[0]) as f:
#     conv = json.load(f)
#     print(f"Step: {conv['step']}")
#     print(f"Timestamp: {conv['timestamp']}")
# ```

# ## 配置和控制

# ### 禁用对话保存
# 如果不需要保存对话（例如在生产环境），可以在函数中添加检查：
# ```python
# # 在_save_llm_conversation开头添加
# if not self.config.save_conversations:  # 需要在config中添加此选项
#     return
# ```

# ### 限制保存的对话数量
# 可以实现自动清理旧对话的功能：
# ```python
# def _cleanup_old_conversations(self, repo_name: str, version: str, keep_last: int = 100):
#     """保留最新的N个对话，删除旧的"""
#     conversations_dir = self._get_result_dir(repo_name, version) / "conversations"
#     conversations = sorted(conversations_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
    
#     if len(conversations) > keep_last:
#         for old_conv in conversations[:-keep_last]:
#             old_conv.unlink()
# ```
import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime

from transformers import AutoTokenizer
from typing import List, Dict, Union, Any
from .logger import get_logger

logger = get_logger(__name__)


def parse_conversation_filename(filename: str):
    """解析对话文件名"""
    parts = filename.split('_')
    if len(parts) >= 4:
        timestamp = f"{parts[0]}_{parts[1]}_{parts[2]}"
        step_name = '_'.join(parts[3:]).replace('.json', '')
        return timestamp, step_name
    return None, None


def load_conversation(filepath: Path):
    """加载对话JSON文件"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.info(f"Error loading {filepath}: {e}")
        return None


def list_conversations(conversations_dir: Path):
    """列出所有对话"""
    logger.info("=" * 80)
    logger.info(f"对话目录: {conversations_dir}")
    logger.info("=" * 80)
    
    conversations = sorted(conversations_dir.glob("*.json"))
    
    if not conversations:
        logger.info("未找到对话文件")
        return
    
    logger.info(f"\n总计 {len(conversations)} 个对话文件:\n")
    
    # 按步骤分组
    by_step = defaultdict(list)
    for conv_file in conversations:
        timestamp, step_name = parse_conversation_filename(conv_file.name)
        if step_name:
            by_step[step_name].append((timestamp, conv_file))
    
    # 显示统计
    for step_name, files in sorted(by_step.items()):
        logger.info(f"{step_name}: {len(files)} 个对话")
    
    logger.info("\n" + "=" * 80)


def show_conversation_summary(conversations_dir: Path):
    """显示对话摘要"""
    conversations = sorted(conversations_dir.glob("*.json"))
    
    logger.info("\n对话摘要:")
    logger.info("-" * 80)
    
    for conv_file in conversations[:10]:  # 只显示前10个
        conv = load_conversation(conv_file)
        if conv:
            timestamp = conv.get('timestamp', 'N/A')
            step = conv.get('step', 'unknown')
            
            logger.info(f"\n文件: {conv_file.name}")
            logger.info(f"  步骤: {step}")
            logger.info(f"  时间: {timestamp}")
            
            # 显示特定信息
            if step == "file_summary":
                logger.info(f"  文件: {conv.get('file_path', 'N/A')}")
            elif step == "module_analysis_iteration":
                logger.info(f"  迭代: {conv.get('iteration', 'N/A')}")
            
            # 显示prompt和response长度
            prompt_len = len(conv.get('prompt', '')) if 'prompt' in conv else 0
            response_len = len(conv.get('response', '')) if 'response' in conv else 0
            logger.info(f"  Prompt长度: {prompt_len} 字符")
            logger.info(f"  Response长度: {response_len} 字符")
    
    if len(conversations) > 10:
        logger.info(f"\n... 还有 {len(conversations) - 10} 个对话未显示")
    
    logger.info("-" * 80)


def view_conversation_detail(conversations_dir: Path, filename: str):
    """查看特定对话的详细内容"""
    filepath = conversations_dir / filename
    
    if not filepath.exists():
        logger.info(f"错误: 文件不存在 {filepath}")
        return
    
    conv = load_conversation(filepath)
    if not conv:
        return
    
    logger.info("=" * 80)
    logger.info(f"对话详情: {filename}")
    logger.info("=" * 80)
    
    logger.info(f"\n步骤: {conv.get('step')}")
    logger.info(f"时间: {conv.get('timestamp')}")
    
    if 'file_path' in conv:
        logger.info(f"文件: {conv['file_path']}")
    
    if 'iteration' in conv:
        logger.info(f"迭代: {conv['iteration']}")
    
    logger.info("\n" + "-" * 80)
    logger.info("PROMPT:")
    logger.info("-" * 80)
    logger.info(conv.get('prompt', 'N/A')[:1000])  # 只显示前1000字符
    if len(conv.get('prompt', '')) > 1000:
        logger.info(f"\n... (还有 {len(conv['prompt']) - 1000} 字符)")
    
    logger.info("\n" + "-" * 80)
    logger.info("RESPONSE:")
    logger.info("-" * 80)
    logger.info(conv.get('response', 'N/A')[:1000])
    if len(conv.get('response', '')) > 1000:
        logger.info(f"\n... (还有 {len(conv['response']) - 1000} 字符)")
    
    logger.info("\n" + "-" * 80)
    logger.info("PARSED RESULT:")
    logger.info("-" * 80)
    parsed = conv.get('parsed_result') or conv.get('parsed_response')
    if parsed:
        logger.info(json.dumps(parsed, indent=2, ensure_ascii=False)[:1000])
    else:
        logger.info("N/A")
    
    logger.info("\n" + "=" * 80)


def analyze_module_iterations(conversations_dir: Path):
    """分析模块分析的迭代过程"""
    module_convs = sorted(conversations_dir.glob("*module_analysis_iter_*.json"))
    
    if not module_convs:
        logger.info("未找到模块分析迭代对话")
        return
    
    logger.info("\n" + "=" * 80)
    logger.info("模块分析迭代过程:")
    logger.info("=" * 80)
    
    for conv_file in module_convs:
        conv = load_conversation(conv_file)
        if conv:
            iteration = conv.get('iteration', '?')
            parsed = conv.get('parsed_response', {})
            action = parsed.get('action', 'unknown')
            thinking = parsed.get('thinking', '')[:100]  # 前100字符
            
            logger.info(f"\n迭代 {iteration}:")
            logger.info(f"  动作: {action}")
            logger.info(f"  思考: {thinking}...")
            
            if action == "finalize":
                modules = parsed.get('modules', [])
                logger.info(f"  识别模块数: {len(modules)}")
    
    logger.info("\n" + "=" * 80)


def main():
    if len(sys.argv) < 2:
        logger.info("使用方法:")
        logger.info("  python view_llm_conversations.py <conversations_dir> [command] [args]")
        logger.info("\n命令:")
        logger.info("  list        - 列出所有对话 (默认)")
        logger.info("  summary     - 显示对话摘要")
        logger.info("  view <file> - 查看特定对话详情")
        logger.info("  iterations  - 分析模块分析的迭代过程")
        logger.info("\n示例:")
        logger.info("  python view_llm_conversations.py output_dir/NeMo/abc123/conversations")
        logger.info("  python view_llm_conversations.py output_dir/NeMo/abc123/conversations summary")
        logger.info("  python view_llm_conversations.py output_dir/NeMo/abc123/conversations view 20251211_143025_123_basic_info.json")
        sys.exit(1)
    
    conversations_dir = Path(sys.argv[1])
    
    if not conversations_dir.exists():
        logger.info(f"错误: 目录不存在 {conversations_dir}")
        sys.exit(1)
    
    command = sys.argv[2] if len(sys.argv) > 2 else "list"
    
    if command == "list":
        list_conversations(conversations_dir)
    elif command == "summary":
        list_conversations(conversations_dir)
        show_conversation_summary(conversations_dir)
    elif command == "view":
        if len(sys.argv) < 4:
            logger.info("错误: 请指定要查看的文件名")
            sys.exit(1)
        view_conversation_detail(conversations_dir, sys.argv[3])
    elif command == "iterations":
        analyze_module_iterations(conversations_dir)
    else:
        logger.info(f"未知命令: {command}")
        sys.exit(1)


def count_conversation_tokens(
    conversation_messages: List[Dict[str, str]], 
    tokenizer_path: str,
    add_generation_prompt: bool = False
) -> int:
    """
    计算给定对话消息列表在特定分词器下的 Token 数量。
    
    该函数使用 `tokenizer.apply_chat_template` 来确保对话被正确地格式化和分词，
    与模型推理时所使用的格式保持一致，从而准确计算 Tokens。
    
    参数:
        conversation_messages (List[Dict[str, str]]): 
            对话历史列表，每个元素都是一个字典，包含 'role' (如 'user', 'assistant', 'system') 
            和 'content' 字段。例如: 
            [{"role": "user", "content": "你好"}, {"role": "assistant", "content": "我很好"}]
        tokenizer_path (str): 
            预训练分词器的路径或 Hugging Face 模型名称 (例如: 'deepseek-chat', './my_model_path')。
        add_generation_prompt (bool): 
            是否在对话末尾添加一个用于提示模型生成响应的特殊 Token。
            如果计算的是完整的输入提示（用于模型生成），应设置为 True。
            如果只是计算已有的对话历史，可以设置为 False。默认为 False。
            
    返回:
        int: 对话历史所包含的 Token 总数量。
    """
    try:
        # 1. 加载分词器
        tokenizer = AutoTokenizer.from_pretrained(tokenizer_path, trust_remote_code=True)
        
        # 2. 应用对话模板并进行分词
        # tokenize=True: 返回一个 Token ID 列表 (List[int])
        # add_generation_prompt: 控制是否添加额外的特殊 Token (如 <|im_start|>assistant)
        inputs: List[int] = tokenizer.apply_chat_template(
            conversation_messages, 
            tokenize=True, 
            add_generation_prompt=add_generation_prompt
        )
        
        # 3. 返回 Token 数量
        return len(inputs)
        
    except Exception as e:
        logger.info(f"计算 Token 数量时发生错误: {e}")
        return 0


if __name__ == "__main__":
    main()

    import json
    
    # 假设你的 conv.json 文件内容大致如下结构:
    # {
    #     "conversation_history": [
    #         {"role": "system", "content": "你是一个乐于助人的助手。"},
    #         {"role": "user", "content": "请问中国最高的山峰是哪座？"},
    #         {"role": "assistant", "content": "中国最高的山峰是珠穆朗玛峰。"}
    #     ]
    # }
    
    # 假设的文件读取逻辑（保持和原代码一致）
    filepath = "conv.json"
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        messages = data['conversation_history']
        
        # 模型的路径或名称
        # 注意: 如果你的模型在本地，请将 'deepseek-chat' 替换为本地路径
        model_name_or_path = 'deepseek-chat'
        
        # 示例 1: 计算完整的对话历史的 Token 数量 (不包括提示模型开始生成)
        token_count_history = count_conversation_tokens(
            conversation_messages=messages, 
            tokenizer_path=model_name_or_path,
            add_generation_prompt=False
        )
        logger.info(f"仅对话历史 (不含生成提示) 的 Token 数量: {token_count_history}")

        # 示例 2: 计算用于模型推理的输入 Token 数量 (通常需要添加生成提示)
        # 只有当 'assistant' 是最后一个角色时，才应该设置为 False。
        # 如果最后一个是 'user'，那么添加 True 会更准确地模拟推理输入。
        token_count_for_inference = count_conversation_tokens(
            conversation_messages=messages, 
            tokenizer_path=model_name_or_path,
            add_generation_prompt=True
        )
        logger.info(f"用于模型推理 (含生成提示) 的 Token 数量: {token_count_for_inference}")

    except FileNotFoundError:
        logger.info(f"错误: 找不到文件 {filepath}。请确保文件存在且路径正确。")
    except json.JSONDecodeError:
        logger.info(f"错误: 文件 {filepath} 不是有效的 JSON 格式。")
    except Exception as e:
        logger.info(f"主程序执行发生错误: {e}")