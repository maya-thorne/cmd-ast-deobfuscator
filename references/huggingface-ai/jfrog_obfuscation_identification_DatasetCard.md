---
license: cc-by-nc-sa-4.0
task_categories:
- text-classification
- token-classification
- feature-extraction
language:
- en
tags:
- jailbreak
- security
- guardrails
---

# Obfuscation Identification Dataset

This repository contains the data used in our paper [Broken-Token: Filtering Obfuscated Prompts by Counting Characters-Per-Token](https://arxiv.org/abs/2510.26847).

While we release this dataset under the CC-by-NC-SA-4.0 license, the dataset was constructed and built on other datasets, each with its own license, as mentioned below:

* [SoftAge-AI/prompt-eng_dataset](https://huggingface.co/datasets/SoftAge-AI/prompt-eng_dataset), MIT License
* [Aiden07/dota2_instruct_prompt](https://huggingface.co/datasets/Aiden07/dota2_instruct_prompt), MIT License
* [hassanjbara/ghostbuster-prompts](https://huggingface.co/datasets/hassanjbara/ghostbuster-prompts), MIT License
* [k-mktr/llm_eval_prompts](https://huggingface.co/datasets/k-mktr/llm_eval_prompts), MIT License
* [facebook/cyberseceval3-visual-prompt-injection](https://huggingface.co/datasets/facebook/cyberseceval3-visual-prompt-injection), MIT License
* [HacksHaven/science-on-a-sphere-prompt-completions](https://huggingface.co/datasets/HacksHaven/science-on-a-sphere-prompt-completions), MIT License
* [grossjct/ethical_decision_making_prompts](https://huggingface.co/datasets/grossjct/ethical_decision_making_prompts), MIT License

## Citation
When using this dataset, please cite it using this bibtex entry:
```
@misc{zychlinski2025brokentokenfilteringobfuscatedprompts,
      title={Broken-Token: Filtering Obfuscated Prompts by Counting Characters-Per-Token}, 
      author={Shaked Zychlinski and Yuval Kainan},
      year={2025},
      eprint={2510.26847},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
      url={https://arxiv.org/abs/2510.26847}, 
}
```
