---
license: apache-2.0
tags:
- generated_from_trainer
model-index:
- name: c-deobfuscate-mt
  results: []
---

<!-- This model card has been generated automatically according to the information the Trainer had access to. You
should probably proofread and complete it, then remove this comment. -->

# c-deobfuscate-mt

This model is a fine-tuned version of [Salesforce/codet5-base](https://huggingface.co/Salesforce/codet5-base) on an unknown dataset.
It achieves the following results on the evaluation set:
- eval_loss: 0.5207
- eval_bleu: 65.8038
- eval_gen_len: 266.6
- eval_runtime: 13.5258
- eval_samples_per_second: 1.109
- eval_steps_per_second: 0.148
- epoch: 40.0
- step: 960

## Model description

More information needed

## Intended uses & limitations

More information needed

## Training and evaluation data

More information needed

## Training procedure

### Training hyperparameters

The following hyperparameters were used during training:
- learning_rate: 2e-05
- train_batch_size: 8
- eval_batch_size: 8
- seed: 42
- optimizer: Adam with betas=(0.9,0.999) and epsilon=1e-08
- lr_scheduler_type: linear
- num_epochs: 100
- mixed_precision_training: Native AMP

### Framework versions

- Transformers 4.20.1
- Pytorch 1.12.0
- Datasets 2.3.2
- Tokenizers 0.12.1

