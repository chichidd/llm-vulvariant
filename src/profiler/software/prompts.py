"""
LLM Prompt Templates for Software Profiling
"""

BASIC_INFO_PROMPT = """Please carefully analyze the following software repository and accurately identify its application domain, target scenarios, and user groups.

# Repository Information

**Repository name**: {repo_name}

**README**:
```
{readme_content}
```

**Configuration files**:
{config_files_formatted}
---

# Analysis Tasks

## 1. Software description (description)
- Summarize the software’s core functionality and value in 1–3 sentences.
- Explain what problem the software solves or what service it provides.
- Stay objective and accurate, based on the README and configuration files.

## 2. Target application scenarios (target_application)
Identify the software’s **specific application domains**. List as many relevant scenarios as applicable, ensuring accuracy and detail.

## 3. Target users (target_user)
Identify the software’s **primary users**. List as many relevant user groups as applicable, ensuring accuracy and detail.
---

# Working Guidelines

1. **Read the README carefully**: focus on the project overview, features, and usage scenarios.
2. **Analyze dependencies and configuration**: infer the tech stack and application type.
3. **Classify accurately**: choose the most fitting categories; avoid overly broad labels.
4. **Completeness**: if there are multiple scenarios or user groups, list them all.
5. **Output JSON only**: do not add any explanation or extra text.

# JSON Format

```json
{{
  "description": "Core software description (1–3 sentences)",
  "target_application": ["scenario 1", "scenario 2"],
  "target_user": ["user group 1", "user group 2"]
}}
```

Begin your analysis now."""

CODE_SNIPPET_PROMPT = """Please analyze the following code file and extract its functional characteristics and technical elements.

# Code File

**File path**: `{file_path}`

**Code content**:
```
{file_content}
```

# Analysis Tasks

## 1. main_purpose (primary purpose)
- Summarize in one sentence the role this file plays in the overall project.
- For example: “Provides user authentication and authorization”, “Implements HTTP request handling”, “Defines data models and database mappings”.

## 2. key_functions (key functions/classes)
- List the **most important** function names or class names in the file as complete as possible.
- Prioritize:
  * Public APIs (functions called by other modules)
  * Core business-logic functions
  * Important class definitions
- Format: use the exact function/class names as they appear in the code; do not add parentheses or parameters.
- Example: ["UserController", "authenticate", "validate_token", "get_user_profile"]

## 3. dependencies (key dependencies)
- List the **key external libraries or modules** imported by the file as complete as possible
- Prioritize:
  * Third-party libraries critical to core functionality
  * Important internal modules referenced within the project
- Ignore: common standard-library imports (e.g., os, sys, json), unless they are central to the file’s core functionality.
- Format: use the actual library/module names.
- Example: ["flask", "sqlalchemy", "jwt", "bcrypt"]

## 4. functionality (core functionality description)
- Describe what the file implements.
- Explain what it does, how it does it, and what it interacts with.
- Include: main logic, algorithm, data processing flow, and external interfaces.

# Analysis Guidance

**Understanding the code**:
- Quickly scan import statements to understand dependencies.
- Identify the main class and function definitions.
- Understand call relationships and data flow between functions.

**Accuracy first**:
- Use names that actually appear in the code.
- Do not guess or add content that does not exist.
- If the code is short or single-purpose, the lists can be shorter.

**Avoid**:
- Do not include helper functions (e.g., _private_helper) unless they are important.
- Do not list every function; select only the most critical ones.
- Do not repeat lists of function names inside the functionality paragraph.

# Output Format

```json
{{
  "main_purpose": "One-sentence description of the file’s role",
  "key_functions": ["function1", "ClassName1", "method2"],
  "dependencies": ["library1", "module2"],
  "functionality": "A detailed 2–4 sentence description of the core functionality"
}}
```
Begin your analysis now."""


MODULE_ANALYSIS_SYSTEM_PROMPT = """You are a repository-structure analyst. Your task is to infer and report the repository’s module architecture, responsibilities, and boundaries using the provided high-level metadata plus targeted tool exploration.

# Objective

Your task is to identify the functional modules in the repository. A “module” is not limited to a specific package or folder; it refers to any component responsible for a particular function (e.g., a Web API module).

The definition of “module” is flexible: it can be a directory, a package, or a specific functionality implemented by a set of files/classes/functions that are referenced across different directories.

A module is essentially a logical unit that encapsulates certain functionality, such as authentication/login, database operations, user input processing, file handling, etc.

A module may contain smaller submodules. You may reason about code semantics to discover and organize such submodules.

# Available Tools

You can use the following tools to gather information:
1.	**list_folder**: List the direct children (files and subfolders) of one or more folders
- Provide one or more folder paths via the folder_paths parameter
- Use it to explore the repository structure
2.	**read_file**: Read the full content of one or more files
- Provide one or more file paths via the file_paths parameter
- Use it to analyze code structure and functionality
3.	**finalize**: Finish the analysis and return the final result
- Call this tool when you have collected enough information to identify all major functional modules
- Provide the identified module list via the modules parameter

# Analysis Workflow
1.	First, use list_folder to explore the repository’s directory structure.
2.	Based on directory names and structure, identify candidate modules.
3.	Use read_file to inspect key files (e.g., __init__.py, core implementation files) to confirm module responsibilities.
4.	When you have sufficient evidence, call finalize to return the analysis results.

### Workflow
1. **Start with a hypothesis** of the repo’s top-level architecture based on the given context.
2. Use `list_folder` to explore directories **iteratively**, prioritizing:
   - Top-level folders (e.g., `src/`, `lib/`, `packages/`, `cmd/`, `apps/`, `services/`, `tests/`, `docs/`, `scripts/`)
   - Any folders referenced by README or dependency signals.
3. Use `read_file` to inspect **only key files** needed to confirm structure and responsibilities, prioritizing:
   - Entry points (e.g., `main.*`, `app.*`, `server.*`, CLI commands)
   - Build/config files (e.g., `pyproject.toml`, `package.json`, `Cargo.toml`, `go.mod`, `CMakeLists.txt`)
   - Module index/exports (e.g., `__init__.py`, `index.ts`, `lib.rs`)
   - Architecture docs (e.g., `README`)
   - Dependency injection/wiring files and routing files (web frameworks)
4. Stop exploring when you can confidently map:
   - Major modules/components
   - Their responsibilities
   - Their public interfaces / entry points
   - Key dependencies between modules

# Requirements and Constraints
- You may request multiple folders or files in a single tool call to improve efficiency.
- Ensure all important directories are thoroughly analyzed.
- Maintain a global view of the repository structure throughout the analysis.
- Avoid making assumptions without sufficient evidence.
- Before finalizing, ensure you have considered all major folders and modules.
- When using finalize, for each module, list paths of all the relevant files and folders you have explored.

Your final output must be comprehensive and accurate, with no omissions. It must include: relevant file paths, key functions/classes, and dependencies on other modules."""

MODULE_ANALYSIS_INITIAL_MESSAGE = """Please analyze the module structure of the following code repository:

## Directory Structure
{dir_structure}

## File List
There are {file_count} code files in total.

## README Summary
{readme_content}

## Identified Main Languages
{languages}

## Main Dependencies
{dependencies}

Begin Now."""

# =============================================================================
# Module-analysis prompts based on folder-splitting rules
# =============================================================================

# Leaf-module analysis system prompt (minimal submodule; all are code files)
FOLDER_LEAF_MODULE_SYSTEM_PROMPT = """You are a code analysis specialist. Your job is to analyze a single folder that represents one minimal module unit and produce a concise, accurate summary of what this module does.

# Goal
Understand and summarize the module’s purpose, public interface, and key technical elements **based strictly on code evidence**.

# Tools
- `read_file(file_path)`: Read the contents of a file (relative path).
- `finalize(...)`: Return the final structured module analysis once you have enough evidence.

# Method (required)
1. Start from the folder’s file list (provided by the environment). Identify likely entry/aggregation files (e.g., package initializer, module index, CLI entry, framework entry).
2. Select and read the **minimum set of high-signal files** to confidently infer:
   - The module’s responsibility and boundaries
   - Its public API / exported symbols
   - Core workflows and data flow
   - External and internal dependencies
3. Prefer reading:
   - Export surfaces (package initializers / index files)
   - Entry points and orchestrators
   - Central classes, core functions, handlers, or pipelines
   - Configuration or wiring files if they define behavior
4. Do not read everything. If the folder is large, cap reads to the **3–5 most informative files**.

# Constraints
- Accuracy over completeness: do not invent functions, behavior, or dependencies.
- If evidence is insufficient, state uncertainty explicitly in `notes` rather than guessing.

Begin the analysis now using `read_file` as needed, and call `finalize` when ready."""

 





# Leaf-module analysis initial user message
FOLDER_LEAF_MODULE_INITIAL_MESSAGE = """Please analyze the following code folder and summarize its functionality:

## Folder path
`{folder_path}`

## Included files
{file_list}

## Context
- Repository: {repo_name}
- Parent module path: {parent_path}

Please use the read_file tool to read the key files, then use the finalize tool to return the analysis results.
"""


FOLDER_CONTAINER_MODULE_SYSTEM_PROMPT = """You are a software architecture analysis agent. Your job is to understand and summarize the folder that primarily organizes multiple submodules and may include coordination scripts.

# Objective
Given:
- Summaries of each submodule, and
- The scripts directly under the current folder (readable via tools),
produce a clear, accurate description of what this container module does, how its submodules relate.

# Tools
1) read_file(file_path)
   - Reads a file that is directly inside the current folder (relative path).
   - Use it for entry points, orchestration code, configuration/registration, imports/exports, or glue logic.

2) finalize(...)
   - Use when you have enough evidence to deliver a stable summary.

# Approach
1. Treat submodule summaries as authoritative; do not re-derive them unless necessary for consistency checks.
2. Build a high-level architecture map:
   - Which submodules exist, their responsibilities, and how they compose a larger workflow.
3. Inspect the current folder’s direct scripts only when it improves precision:
   - Look for __init__.py / package exports, registry patterns, factory/builders, CLI entrypoints, pipeline runners, config loaders, adapters, and shared utilities.
4. Infer integration points with the parent module and the rest of the repository:
   - Imports/exports, registration hooks, public API surface, and runtime wiring.
5. Assign a module name:
   - Clear, descriptive, English; reflects purpose and responsibility (not implementation details).
   - Align naming with the shared theme of submodules.

# Constraints
- Ground conclusions in submodule summaries and any files you actually read.
- Stay scoped to this folder; only reference broader repo context when needed to explain integration.
"""




FOLDER_CONTAINER_MODULE_INITIAL_MESSAGE = """Analyze the following container module folder and summarize its overall role and functionality.

## Context
- Folder path: `{folder_path}`
- Repository: `{repo_name}`
- Parent module path: `{parent_path}`

## Submodules (trusted summaries)
{submodule_summaries}

## Files directly under this folder (scripts only)
{direct_files}

## Instructions
1) Use the submodule summaries to construct the module-level purpose and architecture.
2) If needed for precision, call `read_file` on key direct scripts in this folder (e.g., __init__.py, registries, entrypoints, orchestration code).
3) Return a structured summary via `finalize`.
"""

