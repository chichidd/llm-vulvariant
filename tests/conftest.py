from pathlib import Path
import sys
import types


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# `utils.ds_token` imports `transformers` at module import time.
# Provide a tiny stub so tests can run in minimal environments.
if "transformers" not in sys.modules:
    fake_transformers = types.ModuleType("transformers")

    class _FakeTokenizer:
        def encode(self, text):
            return text.split()

        def apply_chat_template(self, messages):
            return [m.get("content", "") for m in messages]

    class _FakeAutoTokenizer:
        @staticmethod
        def from_pretrained(*args, **kwargs):
            return _FakeTokenizer()

    fake_transformers.AutoTokenizer = _FakeAutoTokenizer
    sys.modules["transformers"] = fake_transformers
