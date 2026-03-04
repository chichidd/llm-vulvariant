#!/usr/bin/env python3
"""
### Conversation history storage directory
```
{output_dir}/
  {repo_name}/
    {version}/
      ├── checkpoints/
      │   ├── repo_info.json
      │   ├── basic_info.json
      │   ├── file_summaries.json
      │   └── modules.json
            ├── conversations/                    # new directory
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


A utility script to view and analyze LLM conversation history.

**Features:**
1. **list**: List all conversation files and show per-step stats
2. **summary**: Show a conversation summary (first 10)
3. **view**: View details of a specific conversation
4. **iterations**: Analyze the iteration process for module analysis

**Usage examples:**
```bash
# List all conversations
python view_llm_conversations.py output_dir/NeMo/abc123/conversations

# Show summary
python view_llm_conversations.py output_dir/NeMo/abc123/conversations summary

# View a specific conversation
python view_llm_conversations.py output_dir/NeMo/abc123/conversations view 20251211_143025_123_basic_info.json

# Analyze iterations
python view_llm_conversations.py output_dir/NeMo/abc123/conversations iterations
```

### Quick view
```bash
# List all conversations
ls -lh output_dir/NeMo/{version}/conversations/

# Show latest conversations
ls -lt output_dir/NeMo/{version}/conversations/ | head

# Filter by conversation type
ls output_dir/NeMo/{version}/conversations/*module_analysis*
```

### JSON formatted view
```bash
# Pretty-print with jq
cat conversations/20251211_143025_123_basic_info.json | jq .

# Print only prompt
cat conversations/20251211_143025_123_basic_info.json | jq .prompt

# Print only response
cat conversations/20251211_143025_123_basic_info.json | jq .response
```


```bash
# Find failed summaries
grep -l "Failed to parse" conversations/*file_summary*.json

# View the failed response
cat conversations/20251211_143026_456_file_summary_problematic.py.json | jq .response
```


# Delete conversations older than 7 days
find profiles/NeMo/*/conversations -name "*.json" -mtime +7 -delete


"""

import json
import sys
from pathlib import Path
from collections import defaultdict

from transformers import AutoTokenizer
from typing import List, Dict
from .logger import get_logger

logger = get_logger(__name__)


def parse_conversation_filename(filename: str):
    """Parse a conversation filename."""
    parts = filename.split('_')
    if len(parts) >= 4:
        timestamp = f"{parts[0]}_{parts[1]}_{parts[2]}"
        step_name = '_'.join(parts[3:]).replace('.json', '')
        return timestamp, step_name
    return None, None


def load_conversation(filepath: Path):
    """Load a conversation JSON file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.info(f"Error loading {filepath}: {e}")
        return None


def list_conversations(conversations_dir: Path):
    """List all conversations."""
    logger.info("=" * 80)
    logger.info(f"Conversation directory: {conversations_dir}")
    logger.info("=" * 80)
    
    conversations = sorted(conversations_dir.glob("*.json"))
    
    if not conversations:
        logger.info("No conversation files found")
        return
    
    logger.info(f"\nTotal {len(conversations)} conversation files:\n")
    
    # Group by step.
    by_step = defaultdict(list)
    for conv_file in conversations:
        timestamp, step_name = parse_conversation_filename(conv_file.name)
        if step_name:
            by_step[step_name].append((timestamp, conv_file))
    # Show stats.
    for step_name, files in sorted(by_step.items()):
        logger.info(f"{step_name}: {len(files)} conversations")
    
    logger.info("\n" + "=" * 80)


def show_conversation_summary(conversations_dir: Path):
    """Show a conversation summary."""
    conversations = sorted(conversations_dir.glob("*.json"))
    
    logger.info("\nConversation summary:")
    logger.info("-" * 80)
    
    for conv_file in conversations[:10]:  # Only show first 10
        conv = load_conversation(conv_file)
        if conv:
            timestamp = conv.get('timestamp', 'N/A')
            step = conv.get('step', 'unknown')
            
            logger.info(f"\nFile: {conv_file.name}")
            logger.info(f"  Step: {step}")
            logger.info(f"  Timestamp: {timestamp}")
            
            # Show step-specific details.
            if step == "file_summary":
                logger.info(f"  File: {conv.get('file_path', 'N/A')}")
            elif step == "module_analysis_iteration":
                logger.info(f"  Iteration: {conv.get('iteration', 'N/A')}")
            
            # Show prompt/response lengths.
            prompt_len = len(conv.get('prompt', '')) if 'prompt' in conv else 0
            response_len = len(conv.get('response', '')) if 'response' in conv else 0
            logger.info(f"  Prompt length: {prompt_len} chars")
            logger.info(f"  Response length: {response_len} chars")
    
    if len(conversations) > 10:
        logger.info(f"\n... {len(conversations) - 10} more conversations not shown")
    
    logger.info("-" * 80)


def view_conversation_detail(conversations_dir: Path, filename: str):
    """View details of a specific conversation."""
    filepath = conversations_dir / filename
    
    if not filepath.exists():
        logger.info(f"Error: file does not exist: {filepath}")
        return
    
    conv = load_conversation(filepath)
    if not conv:
        return
    
    logger.info("=" * 80)
    logger.info(f"Conversation details: {filename}")
    logger.info("=" * 80)
    
    logger.info(f"\nStep: {conv.get('step')}")
    logger.info(f"Timestamp: {conv.get('timestamp')}")
    
    if 'file_path' in conv:
        logger.info(f"File: {conv['file_path']}")
    
    if 'iteration' in conv:
        logger.info(f"Iteration: {conv['iteration']}")
    
    logger.info("\n" + "-" * 80)
    logger.info("PROMPT:")
    logger.info("-" * 80)
    logger.info(conv.get('prompt', 'N/A')[:1000])  # Only show first 1000 chars
    if len(conv.get('prompt', '')) > 1000:
        logger.info(f"\n... ({len(conv['prompt']) - 1000} more chars)")
    
    logger.info("\n" + "-" * 80)
    logger.info("RESPONSE:")
    logger.info("-" * 80)
    logger.info(conv.get('response', 'N/A')[:1000])
    if len(conv.get('response', '')) > 1000:
        logger.info(f"\n... ({len(conv['response']) - 1000} more chars)")
    
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
    """Analyze the module-analysis iteration process."""
    module_convs = sorted(conversations_dir.glob("*module_analysis_iter_*.json"))
    
    if not module_convs:
        logger.info("No module-analysis iteration conversations found")
        return
    
    logger.info("\n" + "=" * 80)
    logger.info("Module analysis iterations:")
    logger.info("=" * 80)
    
    for conv_file in module_convs:
        conv = load_conversation(conv_file)
        if conv:
            iteration = conv.get('iteration', '?')
            parsed = conv.get('parsed_response', {})
            action = parsed.get('action', 'unknown')
            thinking = parsed.get('thinking', '')[:100]  # First 100 chars
            
            logger.info(f"\nIteration {iteration}:")
            logger.info(f"  Action: {action}")
            logger.info(f"  Thinking: {thinking}...")
            
            if action == "finalize":
                modules = parsed.get('modules', [])
                logger.info(f"  Modules identified: {len(modules)}")
    
    logger.info("\n" + "=" * 80)


def main():
    if len(sys.argv) < 2:
        logger.info("Usage:")
        logger.info("  python view_llm_conversations.py <conversations_dir> [command] [args]")
        logger.info("\nCommands:")
        logger.info("  list        - list all conversations (default)")
        logger.info("  summary     - show summary")
        logger.info("  view <file> - view conversation details")
        logger.info("  iterations  - analyze module-analysis iterations")
        logger.info("\nExamples:")
        logger.info("  python view_llm_conversations.py output_dir/NeMo/abc123/conversations")
        logger.info("  python view_llm_conversations.py output_dir/NeMo/abc123/conversations summary")
        logger.info("  python view_llm_conversations.py output_dir/NeMo/abc123/conversations view 20251211_143025_123_basic_info.json")
        sys.exit(1)
    
    conversations_dir = Path(sys.argv[1])
    
    if not conversations_dir.exists():
        logger.info(f"Error: directory does not exist: {conversations_dir}")
        sys.exit(1)
    
    command = sys.argv[2] if len(sys.argv) > 2 else "list"
    
    if command == "list":
        list_conversations(conversations_dir)
    elif command == "summary":
        list_conversations(conversations_dir)
        show_conversation_summary(conversations_dir)
    elif command == "view":
        if len(sys.argv) < 4:
            logger.info("Error: please specify a filename to view")
            sys.exit(1)
        view_conversation_detail(conversations_dir, sys.argv[3])
    elif command == "iterations":
        analyze_module_iterations(conversations_dir)
    else:
        logger.info(f"Unknown command: {command}")
        sys.exit(1)


def count_conversation_tokens(
    conversation_messages: List[Dict[str, str]], 
    tokenizer_path: str,
    add_generation_prompt: bool = False
) -> int:
    """
    Compute the number of tokens for a conversation under a specific tokenizer.

    This function uses `tokenizer.apply_chat_template` to ensure the conversation is formatted
    and tokenized consistently with model inference, enabling accurate token counting.

    Args:
        conversation_messages (List[Dict[str, str]]):
            Conversation history; each item is a dict with 'role' (e.g., 'user', 'assistant', 'system')
            and 'content'. Example:
            [{"role": "user", "content": "Hello"}, {"role": "assistant", "content": "I'm fine"}]
        tokenizer_path (str):
            Path to a pretrained tokenizer or a Hugging Face model name (e.g., 'deepseek-chat', './my_model_path').
        add_generation_prompt (bool):
            Whether to add a special token at the end of the conversation to prompt generation.
            Set to True when counting a full input prompt used for generation; set to False when counting
            an existing conversation history. Default is False.

    Returns:
        int: Total token count of the conversation history.
    """
    try:
        # 1. Load tokenizer
        tokenizer = AutoTokenizer.from_pretrained(tokenizer_path, trust_remote_code=True)
        
        # 2. Apply chat template and tokenize
        # tokenize=True: returns a list of token IDs (List[int])
        # add_generation_prompt: whether to add extra special tokens (e.g., <|im_start|>assistant)
        inputs: List[int] = tokenizer.apply_chat_template(
            conversation_messages, 
            tokenize=True, 
            add_generation_prompt=add_generation_prompt
        )
        
        # 3. Return token count
        return len(inputs)
        
    except Exception as e:
        logger.info(f"Error while counting tokens: {e}")
        return 0


if __name__ == "__main__":
    main()

    import json
    
    # Assume your conv.json roughly looks like:
    # {
    #     "conversation_history": [
    #         {"role": "system", "content": "You are a helpful assistant."},
    #         {"role": "user", "content": "What is the highest mountain in China?"},
    #         {"role": "assistant", "content": "The highest mountain in China is Mount Everest."}
    #     ]
    # }
    
    # Example file reading logic (kept consistent with the original code)
    filepath = "conv.json"
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        messages = data['conversation_history']
        
        # Model path or name
        # Note: if your model is local, replace 'deepseek-chat' with a local path.
        model_name_or_path = 'deepseek-chat'
        
        # Example 1: Token count for the conversation history (without generation prompt)
        token_count_history = count_conversation_tokens(
            conversation_messages=messages, 
            tokenizer_path=model_name_or_path,
            add_generation_prompt=False
        )
        logger.info(f"Conversation history tokens (no generation prompt): {token_count_history}")

        # Example 2: Token count for inference input (often needs generation prompt)
        # Only set to False when 'assistant' is the last role.
        # If the last role is 'user', setting True more accurately simulates inference input.
        token_count_for_inference = count_conversation_tokens(
            conversation_messages=messages, 
            tokenizer_path=model_name_or_path,
            add_generation_prompt=True
        )
        logger.info(f"Inference input tokens (with generation prompt): {token_count_for_inference}")

    except FileNotFoundError:
        logger.info(f"Error: file not found: {filepath}. Please ensure the file exists and the path is correct.")
    except json.JSONDecodeError:
        logger.info(f"Error: file {filepath} is not valid JSON.")
    except Exception as e:
        logger.info(f"Error while running main program: {e}")
