# Checklist: Agents, Orchestration & Tooling

## Scope
Covers agentic system building blocks: tool/function calling, planners, multi-step workflows, graph-based orchestration, memory/state, and integrations.

## Include when you see
- Agent abstractions (Agent/Tool/Planner/Executor), function calling schemas, tool registry.
- Workflow engines (LangGraph-like), DAG/state machine execution.
- Memory: chat history stores, vector memory, episodic memory.
- Integrations with external tools (GitHub, Slack, Notion), or prompt/workflow templates.

## Exclude / avoid double counting
- Retrieval primitives belong in **RAG & Retrieval**; the orchestration that invokes retrieval belongs here.
- Pure UI flow editors belong in **UI & Workflow**.

## Common signals
- Directories: `agents/`, `tools/`, `prompts/`, `chains/`, `graphs/`, `workflow/`, `memory/`.
- Keywords: `function_call`, `tool_call`, `agent`, `planner`, `executor`, `router`, `state graph`, `prompt template`.

## Typical submodules
- Tool interface & adapters
- Planning/routing & control flow
- Memory/state management
- Integrations

## Evidence to collect
- Base agent interfaces and tool schema definitions.
- Example workflows or demos that show multi-step tool use.
