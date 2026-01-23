---
name: ai-infra-module-modeler-noscript
description: Without scripts, classify AI/LLM infrastructure repositories into a hierarchical module taxonomy using LLM semantic analysis. Generate module maps and profiles for vulnerability analysis and documentation.
---

## When to Use
- Analyzing AI/LLM framework repositories to understand module structure
- Creating structured documentation of repository architecture

## Inputs
- Repository path (local directory) as [PROJECT_DIR]
- Output directory (default is ~/vuln/analysis)

## Outputs

- **`MODULES.md`**: Human-readable summary with evidence and taxonomy. The file contains a list of modules identified in the repository and lists of files corresponding to the module after each module section. The example format can be
```markdown
# Module1.FinegrainedModule1
- file1
- file2

# Module1.FinegrainedModule2
- file3
- file4

# Module2.Fingrainedmodule1
- file5
- file6
```

## AI Infra Taxonomy

**Full reference**: [references/taxonomy.md](references/taxonomy.md)

Each coarse category has fine-grained subcategories (e.g., `training_optimization.distributed_training`).

## Execution Procedure

### Step 1: Discover Repository Files

**Scan target repository with these rules:**

**Include files (code only):**
- Code extensions: `.py`, `.pyi`, `.go`, `.rs`, `.java`, `.kt`, `.scala`, `.c`, `.cc`, `.cpp`, `.h`, `.hpp`, `.cu`, `.cuh`, `.sh`, `.bash`, `.ps1`

**Exclude directories:**
- environment folder, like `.git`, `.hg`, `.svn`, `.tox`, `.venv`, `venv`, `__pycache__`, `.mypy_cache`, etc.
- `node_modules`, `dist`, `build`, `target`, `out`, etc.
- `bazel-bin`, `bazel-out`, `bazel-testlogs`, `bazel-workspace`, etc.
- setting folder, `.idea`, `.vscode`, `.pytest_cache`, etc.
- testing-related, like `test`
- doc or manual-related, like `doc`
- any other folder that you decide not related to the main code of the repository

**Output:** List of relative file paths from repository root

### Step 2: Identify Key Files and Group Files by Directory

2.1 Ignore any folder or files that are not related to the code implementation of the project (e.g., [PROJECT_DIR]/asset/, [PROJECT_DIR]/doc which only contains texts, etc)

**Grouping strategy:**
- Group all files sharing same directory prefix
- Sort files within each group alphabetically

**Sample selection per group:**
- Select up to 20 representative file paths
- Prioritize files from start of alphabetical list for reproducibility

**Output:** Dictionary mapping group keys to file lists with snippets

### Step 3: Classify Groups with LLM

3.1 For each group, make sure you have the semantic understanding of the group summaries. If you cannot have fully understood a group or are not certain, you can read any file under the group to make you understand.

3.2 After you are confident that you have *fully* understood the semantic meaning of the files within the group, classify the module name of each file of the group.
- If you decide the files within the group may be belong to two different modules, you can split the original group into different group and make sure each newly splitted group has files belonging to the same module.

Rules:
- Use only the taxonomy keys provided below.
- If fine-grained module is unclear, use the coarse key.


Taxonomy keys (JSON):
```json
{all coarse → fine mappings}
```

Taxonomy reference:
```markdown
{full taxonomy.md content}
```

Groups to classify (JSON):
```json
[{group, file_count, sample_paths, snippets: [{path, content}]}]
```

**Output:** Dictionary mapping group → module assignment

### Step 4: Build File Index

**For each file in repository:**
- Find its group key (by directory depth)
- Look up group's module assignment from Step 3
- Normalize module name: split `coarse.fine`, validate both parts
- If fine not in taxonomy, use first fine from coarse category
- Store mapping: `file_path → coarse.fine`

**Output:** `file_index.json` with all file → module mappings

### Step 5: Generate Module Profile

**For each module in file_index:**

**Create module entry:**
```json
{
  "name": "coarse.fine",
  "category": "coarse",
  "description": "{Fine} responsibilities within {Coarse}. Key areas: {top_3_dirs}.",
  "paths": ["sorted unique file paths"],
  "key_functions": [],
  "dependencies": []
}
```

**Generate description:**
- Convert `training_optimization` → "Training Optimization"
- Convert `distributed_training` → "Distributed Training"
- Find top 3 directories by file count from this module's files
- Append: "Key areas: dir1, dir2, dir3."

**Output:** `module_profile.json` with modules array

### Step 6: Validate Results

1. Read the generated `module_profile.json` and **Use checklists in `references/checklists/` to verify:**
- Each module has appropriate file types
- Module boundaries make semantic sense
- No misclassifications

**If inconsistencies/misclassifications found:**
1. Read actual files in repository
2. Compare against taxonomy definitions in `references/taxonomy.md`
3. Manually correct `file_index.json` if needed
4. Re-generate `module_profile.json` from corrected index

2. Verify that no code file is missed during analysis. If there is missing code files, repeat the above procedures.

## References
- **Taxonomy**: [references/taxonomy.md](references/taxonomy.md) - Full 13-category hierarchy
- **Checklists**: [references/checklists/](references/checklists/) - Per-module validation criteria