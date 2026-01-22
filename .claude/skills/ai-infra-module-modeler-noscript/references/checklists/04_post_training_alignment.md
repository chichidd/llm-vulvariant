# Checklist: Post-training & Alignment

## Scope
Covers **post-training workflows** applied after base pretraining: SFT, PEFT, preference optimization (DPO/GRPO/etc.), RLHF/RLAIF, reward modeling, distillation.

## Include when you see
- LoRA/QLoRA/adapters, merge/adapt scripts, PEFT configs.
- Preference learning implementations (DPO/GRPO/KTO/ORPO, reward modeling).
- RLHF pipelines: rollout generation, reward function/model, PPO-like loops.

## Exclude / avoid double counting
- Pure training engine primitives (optimizers, DDP/FSDP, checkpointing) belong in **Training & Optimization**.
- Prompt templates and tool calling belong in **Agent Orchestration & Workflows** or **RAG & Tooling** depending on usage.

## Common (but not all) signals
- Directories: `sft/`, `lora/`, `peft/`, `dpo/`, `rlhf/`, `reward/`, `preference/`.
- Keywords: `LoRA`, `QLoRA`, `adapter`, `merge_lora`, `DPO`, `GRPO`, `KTO`, `PPO`, `RM`, `reward model`.
- Dependencies: `trl`, `peft`, `trlx`.

## Typical submodules
- SFT recipes
- PEFT adapters + merging
- Preference optimization
- RLHF orchestration

## Evidence to collect
- CLI flags/configs indicating SFT/DPO/RLHF.
- Training scripts explicitly for alignment.
- Docs describing post-training objectives.
