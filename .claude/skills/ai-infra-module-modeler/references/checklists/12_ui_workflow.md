# Checklist: UI, Workflow Builders & Developer Experience

## Scope
Covers developer/operator experience layers: web UIs, workflow builders, CLIs, templates, and dashboards that sit on top of training/serving/RAG engines.

## Include when you see
- Visual flow builders (nodes/edges), UI for composing RAG pipelines or agents.
- Chat UIs with model management (local or server), prompt workspaces.
- CLI tooling for common workflows (download models, start server, run eval).

## Exclude / avoid double counting
- Backend inference runtime stays in **Inference Engine & Acceleration**.
- Pure deployment manifests stay in **Serving & Deployment** unless UI is central.

## Common signals
- Directories: `ui/`, `web/`, `frontend/`, `dashboard/`, `studio/`, `playground/`.
- Files: `package.json`, `pnpm-lock.yaml`, `vite.config.*`, `next.config.*`, `Dockerfile` for UI.
- Keywords: `react`, `nextjs`, `vue`, `svelte`, `react-flow`, `streamlit`, `gradio`.

## Typical submodules
- UI frontend + API client
- Workflow templates/examples
- CLI wrappers
- Developer docs and quickstarts

## Evidence to collect
- Screenshots/README sections describing UI and workflow building
- Entry points for UI/CLI commands
