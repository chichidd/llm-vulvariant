# Checklist: Safety & Security

## Scope
Covers safety guardrails and security controls relevant to AI infra repos: content filtering, policy enforcement, sandboxing, supply-chain checks, secrets handling, vulnerability scanning, and secure-by-default guidance.

## Include when you see
- Guardrails: prompt injection defenses, tool sandboxing, allow/deny lists, policy engines.
- Content safety: filtering, moderation, PII redaction, jailbreak detection.
- Supply chain: SBOM generation, dependency pinning, signature verification, provenance.
- Security docs: threat model notes, hardening guides, secure defaults.

## Exclude / avoid double counting
- Generic auth/rate limiting that is not security-focused belongs to **Serving & Deployment**.
- General unit tests without safety focus belong to **Evaluation & Benchmarking**.

## Common signals
- Files: `SECURITY.md`, `CODEOWNERS`, `.github/workflows/*security*`, SBOM tooling configs.
- Keywords: `CVE`, `SBOM`, `SLSA`, `cosign`, `provenance`, `secret`, `sanitize`, `escape`, `prompt injection`.

## Typical submodules
- Policy/guardrail layer
- Sandbox/permissioning for tools and plugins
- Supply-chain security and dependency hygiene
- Security testing & hardening guidance

## Evidence to collect
- Exact config paths for scanners/policies
- Documentation sections describing hardening and safe deployment
