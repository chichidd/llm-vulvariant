# Checklist: Training & Optimization

## Scope
Covers **pretraining / finetuning training loops** and the optimization stack: distributed training, checkpointing, schedulers, config recipes.

## Include when you see
- Trainer/engine abstractions for forward/backward, gradient accumulation, logging.
- Distributed training (DDP, FSDP, ZeRO, tensor/pipeline parallel, MoE).
- Checkpoint save/restore/resume, sharded ckpts.
- Config management (Hydra, YAML recipes, launch scripts).

## Exclude / avoid double counting
- If the focus is post-training (LoRA/DPO/RLHF), place those parts under **Post-training & Alignment**, but you can still tag shared trainer utilities here.

## Common signals
- Directories: `train/`, `training/`, `pretrain/`, `scripts/train*`, `recipes/`.
- Keywords: `torch.distributed`, `deepspeed`, `fsdp`, `zero`, `megatron`, `ddp`, `optimizer`, `scheduler`, `checkpoint`, `grad_accum`.
- Files: launchers (`torchrun`, `deepspeed`), configs (`*.yaml`) referencing world size.

## Typical submodules
- Training loop / trainer
- Distributed parallelism
- Optimizers and schedules
- Checkpointing / fault tolerance
- Experiment config & launch

## Evidence to collect
- Entry-point training scripts and their config files.
- Docs describing scaling/parallelism.
- Key optimizer/parallel modules.
