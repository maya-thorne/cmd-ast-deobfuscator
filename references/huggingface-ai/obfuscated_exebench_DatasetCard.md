---
license: mit
task_categories:
- translation
language:
- en
tags:
- assembly
- deobfuscation
- llvm-ir
- aarch64
- binary-analysis
- reverse-engineering
- code
- obfuscation
- tigress
- exebench
pretty_name: Obfuscated ExeBench (AArch64)
size_categories:
- 100K<n<1M
configs:
- config_name: default
  data_files:
  - split: train
    path: data/train-*
  - split: test_flatten
    path: data/test_flatten-*
  - split: test_encode_arithmetic
    path: data/test_encode_arithmetic-*
  - split: test_combined
    path: data/test_combined-*
dataset_info:
  features:
  - name: fname
    dtype: string
  - name: func_def
    dtype: string
  - name: technique
    dtype: string
  - name: clean_asm
    dtype: string
  - name: obfuscated_asm
    dtype: string
  - name: clean_ir
    dtype: string
  - name: obfuscated_c
    dtype: string
  - name: tigress_seed
    dtype: int64
  - name: exebench_split
    dtype: string
  - name: c_deps
    dtype: string
  - name: func_c_signature
    dtype: string
  - name: cpp_wrapper
    dtype: string
  - name: dummy_funcs
    dtype: string
  - name: io_pairs
    dtype: string
  splits:
  - name: train
    num_bytes: 10559367144
    num_examples: 980000
  - name: test_flatten
    num_bytes: 130049242
    num_examples: 3909
  - name: test_encode_arithmetic
    num_bytes: 126010317
    num_examples: 3908
  - name: test_combined
    num_bytes: 131099302
    num_examples: 3909
  download_size: 1192158603
  dataset_size: 10946526005
---

# Obfuscated ExeBench (AArch64)

A large-scale dataset of **obfuscated AArch64 assembly** functions paired with their **clean LLVM IR**, original **C source code**, and **clean assembly**.  Designed for training neural models that can **deobfuscate** and **lift** obfuscated binary code.

## Dataset Summary

| Property | Value |
|---|---|
| **Training samples** | ~980,000 (from ExeBench `train_synth_compilable`) |
| **Test samples** | 11,726 (3,909 Flatten / 3,908 EncodeArithmetic / 3,909 Combined) |
| **Test source** | ExeBench `test_synth` (unseen functions) |
| **Architecture** | AArch64 (ARM64) |
| **Obfuscator** | [Tigress 4.0.11](https://tigress.wtf/) |
| **Compiler** | `aarch64-linux-gnu-gcc 15.2.0` (`-S -O0 -std=c11 -w`) |
| **Techniques** | Control-Flow Flattening, Arithmetic Encoding, Combined |
| **Format** | Parquet with Snappy compression |

## Splits

| Split | Rows | Source | Techniques |
|---|---|---|---|
| `train` | ~980,000 | ExeBench `train_synth_compilable` | All three (balanced ⅓ each) |
| `test_flatten` | 3,909 | ExeBench `test_synth` | Flatten only |
| `test_encode_arithmetic` | 3,908 | ExeBench `test_synth` | EncodeArithmetic only |
| `test_combined` | 3,909 | ExeBench `test_synth` | Flatten+EncodeArithmetic |

## Columns

| Column | Type | Description |
|---|---|---|
| `fname` | `string` | Function name |
| `func_def` | `string` | Original C source code of the function |
| `technique` | `string` | Obfuscation technique applied |
| `clean_asm` | `string` | Clean AArch64 assembly from ExeBench (`angha_gcc_arm_O0`) |
| `obfuscated_asm` | `string` | Obfuscated AArch64 assembly (after Tigress → GCC) |
| `clean_ir` | `string` | Clean LLVM IR from ExeBench (`angha_clang_ir_O0`) |
| `obfuscated_c` | `string` | Tigress-obfuscated C source (target function only, runtime stripped) |
| `tigress_seed` | `int32` | Random seed used for Tigress (for reproducibility) |
| `exebench_split` | `string` | Source ExeBench split name |

## Usage

```python
from datasets import load_dataset

# Training data (all techniques)
train = load_dataset("leachl/obfuscated-exebench", split="train", streaming=True)

# Test sets (one per technique, from unseen test_synth functions)
test_flat = load_dataset("leachl/obfuscated-exebench", split="test_flatten")
test_ea   = load_dataset("leachl/obfuscated-exebench", split="test_encode_arithmetic")
test_comb = load_dataset("leachl/obfuscated-exebench", split="test_combined")
```

## Obfuscation Techniques

Each function is independently obfuscated with one of three Tigress transformations:

| Technique | Tigress Flag | Description |
|---|---|---|
| `Flatten` | `--Transform=Flatten` | Control-flow flattening — replaces structured control flow with a switch-in-a-loop dispatcher |
| `EncodeArithmetic` | `--Transform=EncodeArithmetic` | Replaces simple arithmetic/boolean expressions with equivalent but complex MBA expressions |
| `Flatten+EncodeArithmetic` | Both transforms | Combined: flattening + arithmetic encoding applied sequentially |

## Tigress Runtime

A representative Tigress runtime (~480 KB, ~7400 lines of C) is stored in `tigress_runtime.c`.
The `obfuscated_c` column contains **only** the target function body (runtime stripped).

## License

MIT — same as the underlying ExeBench dataset.

