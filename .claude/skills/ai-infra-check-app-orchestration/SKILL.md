---
name: ai-infra-check-app-orchestration
description: Determine whether a repository contains LLM app infra (RAG, agents, workflows, orchestration frameworks) and record evidence.
metadata:
  short-description: Check RAG/agents/workflow modules
---

# ai-infra-check-app-orchestration

## Scope
Frameworks that compose LLM calls into applications: chains, RAG, agents, tool calling, and workflows.

### Evidence checklist
Provide 2+ signals:
1. Dependencies/imports: `langchain`, `llama_index`, `haystack`, `rag`, `agent`, `tool`.
2. Components: retrievers, prompt templates, memory/state, routers, planners/executors.
3. Workflow runtime: DAG/pipeline/state-machine abstractions; task execution backends (`ray`, `celery`).
4. Integrations: vector stores, document loaders, tool registries.

### Fine-grained labels
- `app_and_orchestration.llm_app_frameworks.*`
- `app_and_orchestration.agents_and_tools.*`
- `app_and_orchestration.workflows.*`

## Output
Record label, evidence file paths, and confidence.
