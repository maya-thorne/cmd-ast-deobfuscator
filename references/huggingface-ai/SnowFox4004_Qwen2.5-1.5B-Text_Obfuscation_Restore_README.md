---
license: apache-2.0
language:
- zh
base_model: Qwen/Qwen2.5-1.5B-Instruct
tags:
- fiction
- text
---

## 效果展示

![image/png](https://cdn-uploads.huggingface.co/production/uploads/6375e9bbe9a874a4b3eeb7c9/jBWqVmKi-gZgaTuTPxnJp.png)

![image/png](https://cdn-uploads.huggingface.co/production/uploads/6375e9bbe9a874a4b3eeb7c9/-4P5MnGxU_Q8SvBq3wbIm.png)

---

## 使用：
1. 以这个训练时用的prompt起手
```bash
以下是一段混淆的文本，请将其还原为正常的文本。
```
2. 后面紧接需要恢复语义的句子，否则容易输出大量无意义内容， 但可以分次给予模型

## 问题：
1. 有时把正确的词进行反混淆导致语义有误
2. 有时会输出上次输出的句子而不是提供给模型的句子


## Usage: 

1. use this prompt to get best result as it's used in sft
```bash
以下是一段混淆的文本，请将其还原为正常的文本。
```
2. provide obfuscated text follow it immediately, or it will output meaningless text

## Issues:
1. sometimes replace right words with wrongs
2. sometimes output the last sentence instead of current


## 免责声明
本模型输出内容基于算法生成，可能存在事实性错误、逻辑偏差、时效滞后等问题。使用者应对输出内容进行独立判断并承担所有风险，开发者不对任何直接/间接损失或后果承担责任。使用者须确保其应用场景符合所在司法管辖区法律法规。

通过本模型访问的第三方内容/服务，其合规性及安全性由第三方负责。开发者不承担由此产生的任何责任。

禁止将本模型用于以下用途（包括但不限于）：
1. 生成违法、侵权、欺诈、歧视、暴力或违反公序良俗等内容
2. 制造虚假信息、实施网络攻击或破坏网络安全
3. 任何可能危及人身安全或国家安全的行为
4. 可能侵害合法权利的行为
