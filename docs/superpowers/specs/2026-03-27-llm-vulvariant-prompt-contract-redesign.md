# LLM-VulVariant Prompt Contract Redesign

## Goal

Redesign the prompt system across the full `llm-vulvariant` pipeline so that:

1. software profiling,
2. vulnerability profiling,
3. agentic scanning,
4. exploitability checking

share a consistent prompt contract instead of each stage independently re-deriving the same semantics.

This redesign is allowed to change intermediate and result JSON formats. Backward compatibility with older output files is not a goal for this iteration.

## Scope

In scope:

- `src/profiler/software/prompts.py`
- `src/profiler/software/basic_info_analyzer.py`
- `src/profiler/software/module_analyzer/*`
- `src/profiler/vulnerability/prompts.py`
- `src/profiler/vulnerability/analyzer.py`
- `src/profiler/vulnerability/models.py`
- `src/scanner/agent/prompts.py`
- `src/scanner/agent/utils.py`
- `src/scanner/checker/skill_checker.py`
- related parsers, result models, tests, and docs

Out of scope:

- changing scanner search algorithms beyond prompt-driven behavior
- changing shared public memory storage format
- building a generic prompt registry framework

## Current Problems

### 1. Prompt contracts are inconsistent across stages

The current pipeline uses multiple prompt families, but they do not expose a shared set of fields that later stages can consume directly.

Examples:

- software basic info only returns `description`, `target_application`, `target_user`
- vulnerability profiling returns source/flow/sink details, but does not reliably emit scanner-ready search terms
- scanner prompt must reconstruct search strategies from prose at runtime
- exploitability checker uses yet another ad hoc JSON schema

### 2. Upstream outputs do not carry enough downstream search guidance

The scanner would benefit from receiving structured:

- dangerous API families
- sink keywords
- source indicators
- variant hypotheses
- negative constraints
- reusable query terms

Instead, these are mostly implicit in free-form descriptions.

### 3. Shared public memory consumption still depends too much on prompt improvisation

Recent E2E evidence showed that prompt wording directly changes `read_shared_public_memory` behavior:

- earlier scanner behavior used an empty shared-memory query too early
- after prompt refinement, the scanner first used focused queries and only fell back to broad reads later

This proves prompt quality is not cosmetic; it directly controls scan strategy.

### 4. Module analysis output is under-specified for later scanner use

Current module analysis focuses on module identification, but does not stably produce:

- entry points
- interface surfaces
- module boundary rationale
- confidence
- evidence paths

Those would be valuable both for scanner prioritization and for prompt grounding.

### 5. Checker prompt mixes too many concerns in one flat instruction block

The exploitability checker prompt currently mixes:

- static validation
- output schema
- Docker verification
- credential handling

This works, but makes model behavior harder to steer and harder to validate.

## Design Principles

### 1. One shared contract across the full pipeline

Every prompt family should speak the same evidence language.

Common fields should include:

- `status`
- `confidence`
- `evidence`
- `evidence_summary`
- `open_questions`
- `assumptions`
- `query_terms`
- `negative_constraints`

### 2. Upstream stages must produce downstream-consumable structure

Prompts should not only summarize what was observed. They must produce fields that later prompts can directly consume.

### 3. Keep prompt behavior staged and explicit

For scanning and exploitability analysis, prompts should encode a visible sequence:

1. understand the vulnerability pattern
2. consult reusable prior observations
3. search focused evidence
4. widen only when needed
5. summarize evidence and uncertainty

### 4. Preserve evidence-first behavior

The redesign should strengthen:

- explicit evidence grounding
- explicit uncertainty handling
- explicit negative evidence
- explicit open questions

## Recommended Contract Changes

## Software Basic Info

Current output is too shallow for similarity and scanner grounding.

New fields:

- `description`
- `target_application`
- `target_user`
- `capabilities`
- `interfaces`
- `deployment_style`
- `operator_inputs`
- `external_surfaces`
- `evidence_summary`
- `confidence`
- `open_questions`

Purpose:

- improve similarity retrieval inputs
- give downstream stages a stable summary of external interfaces and operator-controlled surfaces

## Module Analysis

The `finalize` result should be upgraded so each module becomes a better scanning primitive.

Recommended module schema:

- `name`
- `category`
- `responsibility`
- `entry_points`
- `files`
- `key_functions`
- `interfaces`
- `depends_on`
- `dependencies`
- `boundary_rationale`
- `evidence_paths`
- `confidence`

Purpose:

- strengthen scanner prioritization
- strengthen module similarity text
- reduce later prompt ambiguity

## Vulnerability Profiling

Keep the four stages, but add a downstream-oriented output contract.

### Source / Flow / Sink stages

Keep current evidence-driven extraction, but normalize:

- `status`
- `confidence`
- `evidence`
- `evidence_summary`
- `open_questions`
- `assumptions`
- `negative_constraints`

### Vulnerability summary stage

Add scanner-ready fields:

- `query_terms`
- `dangerous_apis`
- `source_indicators`
- `sink_indicators`
- `variant_hypotheses`
- `negative_constraints`
- `likely_false_positive_patterns`
- `scan_start_points`

Purpose:

- allow scanner prompts to begin from structured search families instead of only prose

## Scanner Prompts

Scanner prompt redesign should make the operating sequence explicit.

System prompt should:

- define the vulnerability pattern
- define evidence-first expectations
- define tool usage priorities
- define how to use shared public memory
- define how to widen search scope

Initial and intermediate user prompts should:

- surface the critical scope
- surface reusable shared observations
- surface focused shared-memory query expectations
- surface next-best search families derived from vulnerability profile fields

Compression prompt should retain:

- `shared_memory_hits`
- `rejected_hypotheses`
- `next_best_queries`
- `evidence_gaps`
- `files_completed_this_iteration`

Purpose:

- improve agent stability
- reduce repeated broad searches
- preserve better guidance between iterations

## Exploitability Checker Prompt

Split the conceptual structure of the prompt, even if it still returns one JSON object.

Recommended top-level sections in output:

- `verdict`
- `verdict_rationale`
- `preconditions`
- `static_evidence`
- `dynamic_plan`
- `docker_verification`
- `open_questions`
- `confidence`

Purpose:

- make static and dynamic reasoning separable
- make fallback parsing and evidence recovery more robust
- keep report and CLI consumers aligned with the richer checker result sections

## Output Format Policy

This redesign will intentionally update result formats.

Decision:

- do not build compatibility adapters for older prompt output formats
- update models, parsers, tests, and docs together

Reason:

- prompt contracts are being redesigned holistically, not patched locally
- compatibility layers would increase complexity and weaken the clarity of the new contract

## Implementation Order

1. Redesign vulnerability prompt schemas and models
2. Redesign scanner prompts and compression prompt
3. Redesign software basic-info and module-analysis prompts
4. Redesign exploitability checker prompt
5. Update parsers, result models, tests, and docs
6. Run full tests
7. Run E2E validation with DeepSeek

## Validation Plan

### Unit and parser validation

- prompt-specific tests for every updated schema
- parser/model tests for all changed output contracts
- regression tests for scanner shared-memory prompting

### Integration validation

- vulnerability profile generation tests
- software profile generation tests
- scanner iteration and memory tests
- exploitability checker structured-output tests

### E2E validation

At minimum:

- DeepSeek scanner E2E
- shared public memory reuse E2E
- focused-query shared-memory read behavior
- exploitability checker E2E on representative findings

## Success Criteria

The redesign is successful when:

1. all prompt families use a visibly more consistent evidence contract
2. vulnerability profiles expose scanner-ready search structure
3. scanner prompt behavior improves without ad hoc manual steering
4. shared public memory is consulted in a focused way before broad scanning
5. checker outputs are easier to parse and validate
6. full test suite and representative E2E runs pass
