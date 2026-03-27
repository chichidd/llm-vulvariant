# LLM-VulVariant Prompt Contract Final Sync

This document records the prompt-contract fields and behaviors currently implemented in `llm-vulvariant`. It is a synchronization document for the shipped contract, not a design proposal.

## Implemented Contract

The pipeline now shares one evidence-oriented contract across profiling, scanning, and exploitability checking.

Common evidence fields used where applicable:

- `status`
- `confidence`
- `evidence`
- `evidence_summary`
- `open_questions`
- `assumptions`
- `negative_constraints`

## Current Outputs

### Software Profile Output

`software_profile.json` stores the following `basic_info` fields:

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

`software_profile.json` stores the following `modules[]` fields:

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

### Vulnerability Profile Output

`vulnerability_profile.json` stores the following evidence fields in `source_features`, `flow_features`, and `sink_features`:

- `status`
- `confidence`
- `evidence`
- `evidence_summary`
- `open_questions`
- `assumptions`
- `negative_constraints`

`vulnerability_profile.json` stores the following scanner-ready summary fields at the top level:

- `query_terms`
- `dangerous_apis`
- `source_indicators`
- `sink_indicators`
- `variant_hypotheses`
- `negative_constraints`
- `likely_false_positive_patterns`
- `scan_start_points`
- `confidence`
- `evidence`
- `evidence_summary`
- `open_questions`
- `assumptions`
- `status`

## Scanner Behavior

The scanner runtime consumes structured vulnerability guidance from the vulnerability profile. The current prompt/runtime path passes through:

- `query_terms`
- `dangerous_apis`
- `source_indicators`
- `sink_indicators`
- `variant_hypotheses`
- `negative_constraints`
- `likely_false_positive_patterns`
- `scan_start_points`
- `open_questions`
- `assumptions`

The scanner prompt sequence currently preserves these behaviors:

- identify the vulnerability pattern from the structured guidance instead of reconstructing it from prose only
- use focused `read_shared_public_memory` queries before broader reads when shared observations are available
- search `PRIORITY-1` scope before widening to related or repo-wide scope
- retain iteration-compression summaries with `shared_memory_hits`, `rejected_hypotheses`, `next_best_queries`, `evidence_gaps`, and `files_completed_this_iteration`

## Checker Outputs

`exploitability.json` stores richer top-level analysis sections for each result:

- `verdict`
- `confidence`
- `verdict_rationale`
- `preconditions`
- `static_evidence`
- `dynamic_plan`
- `docker_verification`
- `open_questions`

`exploitability.json` also retains legacy compatibility sections that are still emitted and consumed by downstream report generation:

- `sink_analysis`
- `source_analysis`
- `attack_scenario`
- `remediation`

Current report generation consumes both groups of checker fields:

- richer sections render dedicated evidence-oriented report sections
- legacy compatibility sections still provide sink/source summaries, attack-scenario rendering, and remediation text
- `docker_verification` remains part of the persisted checker result and report output

## Validation Evidence

The current contract is covered by existing tests:

- `tests/test_profile_models_and_storage.py` covers software-profile and vulnerability-profile field persistence
- `tests/test_agent_prompts.py` covers structured scanner guidance and focused shared-memory prompt behavior
- `tests/test_agent_utils.py` covers iteration-compression payload fields
- `tests/test_skill_checker.py` covers checker prompt schema and result normalization
- `tests/test_report_generator.py` covers report consumption of richer checker fields and legacy compatibility sections
