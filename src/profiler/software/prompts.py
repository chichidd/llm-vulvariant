"""
LLM Prompt Templates for Software Profiling
"""

SOFTWARE_BASIC_INFO_SYSTEM_PROMPT = """You are a senior software analysis assistant.
Follow the user's task strictly, ground conclusions in provided repository evidence, and output JSON only."""

BASIC_INFO_PROMPT = """Please carefully analyze the following software repository and accurately identify its application domain, operational context, and external surfaces.

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

## 4. Core capabilities (capabilities)
List the software's major capabilities or services. Use short, concrete phrases grounded in repository evidence.

## 5. Interfaces (interfaces)
List the primary interfaces the software exposes or relies on, such as CLI, HTTP API, SDK/library entry points, web UI, or background workers.

## 6. Deployment style (deployment_style)
List the deployment or execution styles supported by the software, such as library, CLI tool, long-running service, containerized service, or plugin.

## 7. Operator inputs (operator_inputs)
List the main inputs operators, developers, or administrators provide to run or configure the software.

## 8. External surfaces (external_surfaces)
List the externally reachable or attacker-relevant surfaces exposed by the software, such as APIs, file ingestion paths, message queues, network listeners, or admin endpoints.

## 9. Evidence summary (evidence_summary)
Provide a brief 1-3 sentence summary of the repository evidence that supports the fields above.

## 10. Confidence (confidence)
Rate your confidence in this summary as `high`, `medium`, or `low`.

## 11. Open questions (open_questions)
List the most important unresolved questions or ambiguities that remain after reviewing the provided evidence.
---

# Working Guidelines

1. **Read the README carefully**: focus on the project overview, features, and usage scenarios.
2. **Analyze dependencies and configuration**: infer the tech stack and application type.
3. **Classify accurately**: choose the most fitting categories; avoid overly broad labels.
4. **Completeness**: if there are multiple scenarios or user groups, list them all.
5. **Stay evidence-backed**: do not invent interfaces, deployments, or external surfaces that are not supported by the provided materials.
6. **Output JSON only**: do not add any explanation or extra text.

# JSON Format

```json
{{
  "description": "Core software description (1–3 sentences)",
  "target_application": ["scenario 1", "scenario 2"],
  "target_user": ["user group 1", "user group 2"],
  "capabilities": ["capability 1", "capability 2"],
  "interfaces": ["interface 1", "interface 2"],
  "deployment_style": ["deployment 1", "deployment 2"],
  "operator_inputs": ["input 1", "input 2"],
  "external_surfaces": ["surface 1", "surface 2"],
  "evidence_summary": "Short evidence-backed summary.",
  "confidence": "high",
  "open_questions": ["question 1", "question 2"]
}}
```

Begin your analysis now."""




MODULE_ANALYSIS_SYSTEM_PROMPT = """You are a repository-structure analyst. Your task is to infer and report the repository’s module architecture, responsibilities, and boundaries using the provided high-level metadata plus targeted tool exploration.

# Objective

Your task is to identify the functional modules in the repository. A “module” is not limited to a specific package or folder; it refers to any component responsible for a particular function (e.g., a Web API module).
A module is essentially a logical unit that encapsulates certain functionality, such as authentication/login, database operations, user input processing, file handling, etc.
A module may contain smaller submodules. You may reason about code semantics to discover and organize such submodules.
The definition is listed in "AI Infrastructure Module Taxonomy".

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
- **IMPORTANT**: Each module MUST include a "category" field with a valid taxonomy classification (format: "coarse.fine")

# Analysis Workflow
1.	First, use list_folder to explore the repository’s directory structure.
2.	Based on directory names and structure, identify candidate modules.
3.	Use read_file to inspect key files (e.g., __init__.py, core implementation files) to confirm module responsibilities.
4.	When you have sufficient evidence, call finalize to return the analysis results.

### Workflow
1. **Start with a hypothesis** of the repo’s top-level architecture based on the given context.
2. Use `list_folder` to explore directories **iteratively**, prioritizing:
   - Top-level folders (e.g., `src/`, `lib/`, `packages/`, `cmd/`, `apps/`, `services/`, `docs/`, `scripts/`)
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
- Your final output must be comprehensive and accurate, with no omissions.
"""

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
