# Checklist: Agent Orchestration & Workflows

## Scope
Covers agentic system building blocks: agent runtimes, planners/executors, multi-step workflows, graph-based orchestration, memory/state, and plugins/integrations.

## Include when you see
- Agent runtimes (planner/executor loops, routing, control flow).
- Workflow engines (LangGraph-like), DAG/state machine execution.
- Memory/state: chat history stores, vector memory, episodic memory.
- Multi-agent coordination or role-based collaboration.
- Plugins/integrations with external systems (GitHub, Slack, Notion).

## Exclude / avoid double counting
- Retrieval primitives belong in **RAG & Tooling**; the orchestration that invokes retrieval belongs here.
- Tool/function calling used specifically for RAG context assembly belongs in **RAG & Tooling**.
- Pure UI flow editors belong in **UI & Developer Experience**.

## Common (but not all) signals
- Directories: `agents/`, `orchestration/`, `graphs/`, `workflow/`, `memory/`, `plugins/`.
- Keywords: `agent`, `planner`, `executor`, `router`, `state graph`, `multi-agent`, `workflow`.

## Typical submodules
- Agent runtimes
- Planning/routing & control flow
- Graph/workflow composition
- Memory/state management
- Plugins & integrations

## Evidence to collect
- Base agent interfaces and tool schema definitions.
- Example workflows or demos that show multi-step tool use.
