#!/usr/bin/env python3
"""测试文本和树形工具"""

print("=" * 60)
print("测试 1: README 文本清理")
print("=" * 60)

from utils.text_utils import clean_readme_for_llm

sample_readme = """
# My Project [![Build Status](https://img.shields.io/travis/user/repo.svg)](https://travis-ci.org/user/repo)

![Logo](https://example.com/logo.png)

## Features

- **Feature 1**: Something _important_
- [Feature 2](https://example.com)

### Installation

```bash
pip install myproject
```

See [documentation](https://docs.example.com) for more details.

<details>
<summary>Click to expand</summary>
Hidden content here
</details>

<!-- This is a comment -->
"""

cleaned = clean_readme_for_llm(sample_readme)
print("原始长度:", len(sample_readme))
print("清理后长度:", len(cleaned))
print("\n清理后的内容:")
print(cleaned)

print("\n" + "=" * 60)
print("测试 2: 目录树构建（去重）")
print("=" * 60)

from utils.tree_utils import build_directory_structure_tree

files = [
    "src/main.py",
    "src/utils/helper.py",
    "src/utils/config.py",
    "src/models/user.py",
    "src/models/post.py",
    "tests/test_main.py",
    "tests/test_utils.py",
    "README.md",
    "setup.py"
]

tree_output = build_directory_structure_tree(files, max_depth=3)
print(tree_output)

print("\n" + "=" * 60)
print("测试 3: 带文件大小的目录树")
print("=" * 60)

from utils.tree_utils import build_directory_structure_with_sizes

files_with_sizes = [
    ("src/main.py", 1024),
    ("src/utils/helper.py", 512),
    ("src/utils/config.py", 256),
    ("src/models/user.py", 2048),
    ("README.md", 4096),
]

tree_with_sizes = build_directory_structure_with_sizes(files_with_sizes, max_depth=2)
print(tree_with_sizes)

print("\n" + "=" * 60)
print("✓ 所有测试完成")
print("=" * 60)
