# Checklist: UI & Developer Experience

## Scope
Covers developer/operator experience layers: visual flow builders, admin consoles, CLIs, SDKs, and related UX tooling that sits on top of training/serving/RAG engines.

## Include when you see
- Visual flow builders (node/graph UI), prompt playgrounds, workflow studios.
- Admin consoles for model/dataset/registry management.
- CLIs/SDKs for common workflows (download models, start server, run eval).

## Exclude / avoid double counting
- Backend inference runtime belongs in **Inference Engine & Acceleration**.
- Deployment manifests belong in **Serving & Deployment** unless UI is central.

## Common (but not all) signals
- Directories: `ui/`, `web/`, `frontend/`, `dashboard/`, `studio/`, `playground/`, `cli/`, `sdk/`.
- Files: `package.json`, `pnpm-lock.yaml`, `vite.config.*`, `next.config.*`, `Dockerfile` for UI.
- Keywords: `react`, `nextjs`, `vue`, `svelte`, `react-flow`, `streamlit`, `gradio`, `typer`, `click`.

## Typical submodules
- Visual flow builders
- Admin consoles
- CLI/SDK tooling
- Developer docs and quickstarts

## Evidence to collect
- Screenshots/README sections describing UI and workflows.
- Entry points for UI/CLI commands.
