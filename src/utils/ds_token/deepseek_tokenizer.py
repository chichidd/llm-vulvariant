import os
import transformers
from typing import List, Dict

# Get the directory where this module is located (contains tokenizer files)
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))

class DSTokenizerCompute:
    def __init__(self, tokenizer_dir: str = None):
        if tokenizer_dir is None:
            tokenizer_dir = _MODULE_DIR
        self.tokenizer = transformers.AutoTokenizer.from_pretrained(
            tokenizer_dir, trust_remote_code=True
        )

    def encode_len(self, text: str):
        return len(self.tokenizer.encode(text))
    
    def apply_chat_template_len(self, messages: List[Dict]):
        return len(self.tokenizer.apply_chat_template(messages))
