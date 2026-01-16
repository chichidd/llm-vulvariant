---
name: ai-infra-check-training
description: Determine whether a repository contains training or fine-tuning infra (loops, distributed strategies, post-training) and record evidence.
metadata:
  short-description: Check training/finetune/post-training modules
---

# ai-infra-check-training

## Scope
Anything that *updates model parameters* or manages training runs.

### Includes
- Pretraining/trainer loops; checkpointing/resume; logging.
- Fine-tuning (SFT, LoRA/QLoRA, adapters, recipes).
- Post-training/alignment (reward modeling, DPO/GRPO, PPO-based RLHF/RLAIF).
- Training efficiency and parallelism (ZeRO/FSDP, tensor/pipeline parallel).

### Evidence checklist
Provide 2+ signals:
1. Code: `Trainer`, `training_step`, `loss.backward`, `optimizer.step`, `gradient_accumulation`.
2. Dependencies: `deepspeed`, `accelerate`, `transformers.Trainer`, `pytorch-lightning`, `megatron`.
3. Configs: `ds_config*.json`, `zero_stage`, `fsdp_config`, distributed launch scripts.
4. Post-training: `dpo`, `ppo`, `reward_model`, `preference` datasets.

### Fine-grained labels
- `training.pretraining.*`
- `training.finetuning.*`
- `training.post_training.*`
- `training.efficiency.*`

## Boundary tests
- If code only performs inference or serving, do not classify as training.
- If code only converts checkpoints/quantizes, classify as `model_assets`.

## Output
Record label, evidence file paths, and confidence.
