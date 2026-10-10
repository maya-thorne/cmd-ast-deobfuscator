<div align="center">

<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="ko.md">🇰🇷 한국어</a> · <a href="zh-CN.md">🇨🇳 中文</a> · <a href="es.md">🇪🇸 Español</a> · <a href="hi.md">🇮🇳 हिन्दी</a><br />
  <a href="ar.md">🇸🇦 العربية</a> · <a href="pt-BR.md">🇧🇷 Português</a> · <a href="ru.md">🇷🇺 Русский</a> · <a href="fr.md">🇫🇷 Français</a> · <strong>🇮🇩 Bahasa Indonesia</strong>
</p>

<p align="center">
  <a href="https://github.com/maya-thorne/cmd-ast-deobfuscator"><img src="../assets/locales/id/banner.svg" alt="cmd-ast-deobfuscator banner" width="100%" /></a>
</p>

# 🛡️ cmd-ast-deobfuscator

**Mesin Analisis Pohon Sintaks Abstrak (AST) & Deobfuskasi Leksikal Multi-Pass untuk Skrip Batch Windows (`cmd.exe` / `.bat`)**

[![CI](https://github.com/maya-thorne/cmd-ast-deobfuscator/actions/workflows/ci.yml/badge.svg)](https://github.com/maya-thorne/cmd-ast-deobfuscator/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Ghidra: RE Forensics](https://img.shields.io/badge/Ghidra-Forensik%20Biner%20Ghidra-red.svg)](docs/BATCH_OBFUSCATION_DEEP_REVERSE_ENGINEERING_ANALYSIS.md)
[![Detection: Sigma & YARA](https://img.shields.io/badge/Detection-Aturan%20Sigma%20%26%20YARA-purple.svg)](rules/)

<sub>Dirancang oleh **[Maya Thorne](https://github.com/maya-thorne)** · Arsitek Sistem Eksploitasi Biner & Rekayasa Balik</sub>

</div>

---

## 📑 Daftar Isi

- [📌 Arsitektur & Landasan Teoretis](#-architecture--theoretical-foundations)
  - [⚙️ Mesin Keadaan (State Machine) Parser 5-Tahap `cmd.exe`](#%EF%B8%8F-cmdexe-5-phase-parser-state-machine)
  - [🔄 Diagram Saluran Deobfuskasi Multi-Pass](#-multi-pass-deobfuscation-pipeline)
- [🛡️ 12 Vektor Obfuskasi Utama yang Ditangani](#%EF%B8%8F-12-major-obfuscation-vectors-countered)
- [🔬 Bedah Kode Sumber: 7 Alat Analisis Terbuka](#-deep-dive-source-code-anatomy-of-7-open-source-tools)
- [🧬 Rekayasa Balik Biner dengan Ghidra](#-ghidra-binary-reverse-engineering-forensics)
- [🚨 Teknik Deteksi (Aturan YARA & Sigma)](#-detection-engineering-yara--sigma-rules)
- [🚀 Panduan Memulai Cepat & CLI](#-quickstart--cli-usage)
- [📊 Verifikasi Otomatis & Tolok Ukur Kinerja](#-automated-invariant-verification--benchmarks)
- [📁 Struktur Pohon Repositori](#-repository-architecture)
- [⚖️ Lisensi & Pengungkapan Bertanggung Jawab](#%EF%B8%8F-license--responsible-disclosure)

---

## 📌 Architecture & Theoretical Foundations

`cmd-ast-deobfuscator` adalah kerangka kerja analisis statis dan deobfuskasi tingkat industri yang dibangun untuk peneliti malware dan analis respons insiden.

### ⚙️ `cmd.exe` 5-Phase Parser State Machine

`cmd.exe` beroperasi menggunakan mesin pemindaian iteratif 5-tahap yang kerap dieksploitasi pelaku ancaman untuk mengelabui deteksi:

1. **Tahap 1: Prapemrosesan Baris & Normalisasi Caret (`^`)** — Memproses pemisahan baris dan membatalkan karakter khusus dengan caret di luar tanda kutip.
2. **Tahap 2: Ekspansi Persen Langsung (`%VAR%`)** — Evaluasi variabel lingkungan, pemotongan substring (`%VAR:~2,5%`), dan substitusi teks.
3. **Tahap 3: Pemisah Sintaksis & Pemipaan (Pipe)** — Memisahkan rantai perintah (`&`, `&&`, `|`, `||`) dan pengelompokan tanda kurung.
4. **Tahap 4: Evaluasi Ekspansi Tertunda (`!VAR!`)** — Evaluasi variabel bertanda seru saat runtime iterasi perulangan.
5. **Tahap 5: Pengiriman Subshell & Argumen** — Ekstraksi nama berkas biner dan argumen akhir untuk dieksekusi.

### 🔄 Multi-Pass Deobfuscation Pipeline

<p align="center">
  <a href="https://github.com/maya-thorne/cmd-ast-deobfuscator"><img src="../assets/cmd_ast_pipeline_architecture.svg" alt="cmd-ast-deobfuscator Architecture" width="100%" /></a>
</p>

```mermaid
flowchart TD
    In["📄 Skrip Batch Terobfuskasi Mentah"] --> P1["1️⃣ Tahap 1: Sanitasi Enkoding & BOM"]
    P1 --> P2["2️⃣ Tahap 2: Normalisasi Caret & Tanda Kutip Kosong"]
    P2 --> P3["3️⃣ Tahap 3: Pelacakan Tabel Simbol Variabel Lingkungan"]
    P3 --> P4["4️⃣ Tahap 4: Evaluator Pemotongan Substring & Substitusi"]
    P4 --> P5["5️⃣ Tahap 5: Rekonstruksi Pohon AST Sintaksis"]
    P5 --> P6["6️⃣ Tahap 6: Eliminasi Kode Mati & Pemformatan"]
    P6 --> Out["✨ Skrip Batch Bersih Terdeobfuskasi"]

    classDef pass fill:#0f172a,stroke:#38bdf8,stroke-width:1.5px,color:#f8fafc;
    classDef start fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#f8fafc;
    classDef clean fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#f8fafc;
    class In start;
    class P1,P2,P3,P4,P5,P6 pass;
    class Out clean;
```

---

## 🛡️ 12 Major Obfuscation Vectors Countered

<details open>
<summary><b>1. Non-Quoted Caret Injection (캐럿 탈출 시퀀스 정화)</b></summary>

- **Mechanism**: The caret character (`^`) serves as an escape operator in `cmd.exe`. Outside quotation marks, inserting carets between characters does not modify runtime semantics but completely fractures static token signatures.
- **Obfuscated**:
  ```cmd
  c^a^l^c^.^e^x^e
  ```
- **Normalized Output**:
  ```cmd
  calc.exe
  ```
</details>

<details>
<summary><b>2. Interleaved Empty Double Quotes (빈 따옴표 접합 기법)</b></summary>

- **Mechanism**: `cmd.exe` collapses contiguous empty quotation strings (`""`) during argument parsing.
- **Obfuscated**:
  ```cmd
  p""o""w""e""r""s""h""e""l""l"".""e""x""e -NoP -w 1
  ```
- **Normalized Output**:
  ```cmd
  powershell.exe -NoP -w 1
  ```
</details>

<details>
<summary><b>3. Environment Variable Substring Slicing (환경변수 인덱스 슬라이싱)</b></summary>

- **Mechanism**: Slicing system environment variables like `%COMSPEC:~start,length%` or negative offsets `%PATH:~-10,1%` to dynamically assemble keywords.
- **Obfuscated**:
  ```cmd
  %COMSPEC:~19,1%%COMSPEC:~24,1%%COMSPEC:~27,1%
  ```
- **Normalized Output**:
  ```cmd
  cmd
  ```
</details>

<details>
<summary><b>4. Dynamic String Substitution (문자열 인라인 치환 패턴)</b></summary>

- **Mechanism**: Exploits batch syntax `%VAR:search=replace%` to embed randomized decoy characters.
- **Obfuscated**:
  ```cmd
  set "X=c_a_l_c"
  %X:_=%
  ```
- **Normalized Output**:
  ```cmd
  calc
  ```
</details>

<details>
<summary><b>5. High-Entropy Randomized Set Variable Chains (난수 변수 배열 셔플링)</b></summary>

- **Mechanism**: Tools like `0xidiz3r` and `Somalifuscator` emit dozens of lines setting chaotic variable arrays like `set a9f=c`, `set b12=a`, and assemble them in subsequent lines.
- **Normalized Output**: Traced via symbol table graph resolver and folded into direct commands.
</details>

<details>
<summary><b>6. UTF-16LE Byte Order Mark & Non-Printable Headers (BOM 은닉 기법)</b></summary>

- **Mechanism**: Injecting `0xFF 0xFE` with zero-width spaces or null bytes causing naive ASCII/UTF-8 loggers to truncate analysis.
- **Normalized Output**: Byte-level header detection and automatic UTF-8 stream normalization.
</details>

<details>
<summary><b>7. Hex/Octal Command Prefix Evasion</b></summary>

- **Mechanism**: Representing parameters or numeric commands in hexadecimal/octal format.
</details>

<details>
<summary><b>8. Bat2Exe PE Packaging & Dropper Stubs</b></summary>

- **Mechanism**: Compiling scripts into PE executables with resource encryption stubs (`BEDeCode`, `Bat2Exe`).
</details>

<details>
<summary><b>9. Anti-Analysis, VM & Sandbox Timing Traps</b></summary>

- **Mechanism**: Inserting `ping 127.0.0.1 -n 30 >nul`, `choice /t 10 /d y`, or registry queries targeting VMware/VirtualBox.
</details>

<details>
<summary><b>10. `for /f` Token Delimiter Reconstruction</b></summary>

- **Mechanism**: Splitting commands using custom delimiters inside nested `for /f "tokens=*" %%a in (...)` blocks.
</details>

<details>
<summary><b>11. Heavy Pipe Chaining (`|`) & Redirection</b></summary>

- **Mechanism**: Chaining commands through ephemeral stdin/stdout buffers to avoid disk artifacts.
</details>

<details>
<summary><b>12. Multi-Stage Polyglot Invocations</b></summary>

- **Mechanism**: Hybrid batch scripts executing embedded PowerShell base64 or VBScript stubs.
</details>

---

## 🔬 Deep Dive: Source Code Anatomy of 7 Open-Source Tools

The suite includes line-by-line dissections and structural references from 7 seminal open-source obfuscation and deobfuscation projects:

| # | Project Name | Author / Origin | Core Mechanism | Deobfuscation Countermeasure |
| :-: | :--- | :--- | :--- | :--- |
| **01** | `Invoke-DOSfuscation` | Daniel Bohannon | Environment variable slicing, string concatenation, token randomization | Multi-pass static symbol evaluator & caret stripper |
| **02** | `0xidiz3r` | 0xIdiot | Chaotic set arrays, unicode spacing, variable permutation | Deterministic symbol table propagation |
| **03** | `SomalifuscatorV2` | KDot227 | Control-flow flattening, dead code spam, junk label loops | Dead code elimination & label graph prune |
| **04** | `batch_deobfuscator` | DissectMalware | Lexical heuristic AST parser | Extended syntactic rule matcher |
| **05** | `Exorcism` | Ares-X | Dynamic variable reconstruction | Variable scope resolution |
| **06** | `Bat2Exe-dehoisted` | JohnDJohnD | PE resource unhoisting & batch extraction | Header extraction & payload recovery |
| **07** | `Batch-Encryption-DeCoder` | Community | Multi-algorithm decryptor for BEDeCode/QuickBatch | Reverse cipher matching |

*Detailed architectural breakdowns and source extractions are available in [`references/source-dissections/`](references/source-dissections/) and [`docs/BATCH_OBFUSCATION_DEEP_REVERSE_ENGINEERING_ANALYSIS.md`](docs/BATCH_OBFUSCATION_DEEP_REVERSE_ENGINEERING_ANALYSIS.md).*

---

## 🧬 Ghidra Binary Reverse Engineering Forensics

We conducted comprehensive Ghidra binary decompilation and memory forensic analysis on 4 key executables associated with batch compilation and runtime evasion:

```
Target Executables Triaged:
├── 01_BEDeCode.exe         (Delphi/Borland PE32, RVA: 0x00401000 - In-memory key decryption)
├── 02_example_obfuscated.exe (Bat2Exe Compiled Stub, Resource Directory: .rsrc RVA: 0x00412000)
├── 03_choice.exe           (System Anti-Sandbox Delay Binary, KERNEL32.Sleep API wrapper)
└── 04_xorStub.exe          (PE Dropper with In-Memory XOR Payload Extraction)
```

### Sample Disassembly: In-Memory Payload Decryptor (`xorStub.exe`)

```nasm
; RVA: 0x00401240 - DecryptPayload Routine
00401240 55              PUSH       EBP
00401241 89 e5           MOV        EBP,ESP
00401243 53              PUSH       EBX
00401244 8b 45 08        MOV        EAX,dword ptr [EBP + 0x8]   ; Pointer to encrypted buffer
00401247 8b 4d 0c        MOV        ECX,dword ptr [EBP + 0xc]   ; Buffer length
0040124a 8a 5d 10        MOV        BL,byte ptr [EBP + 0x10]    ; XOR Key (0x5A)
0040124d 85 c9           TEST       ECX,ECX
0040124f 74 0c           JZ         0x0040125d
00401251 30 18           XOR        byte ptr [EAX],BL          ; In-place Byte Unmasking
00401253 40              INC        EAX
00401254 49              DEC        ECX
00401255 75 fa           JNZ        0x00401251
0040125d 5b              POP        EBX
0040125e 5d              POP        EBP
0040125f c3              RET
```

---

## 🚨 Detection Engineering (YARA & Sigma Rules)

Production-ready detection rules targeting evasive batch artifacts are located in [`rules/`](rules/):

- **Sigma**: [`rules/sigma_batch_obfuscation.yml`](rules/sigma_batch_obfuscation.yml) — Detects high caret frequency (`^ > 10`), environment variable slicing (`%COMSPEC:~`), and nested subshell concatenations.
- **YARA**: [`rules/yara_batch_obfuscation.yar`](rules/yara_batch_obfuscation.yar) — Pattern matching for Somalifuscator signatures, 0xidiz3r arrays, and Bat2Exe PE dropper stubs.

---

## 🚀 Quickstart & CLI Usage

### Prerequisites
- Python 3.10 or higher
- Git

### Installation

```bash
git clone https://github.com/maya-thorne/cmd-ast-deobfuscator.git
cd cmd-ast-deobfuscator
```

### CLI Command Options

```bash
# Deobfuscate a single batch file
python src/deobfuscator_engine.py -i samples/01_env_slicing_sample.bat -o deobfuscated_output.bat

# Verbose inspection mode with pass-by-pass telemetry
python src/deobfuscator_engine.py -i samples/02_caret_and_quote_sample.bat --verbose
```

---

## 📊 Automated Invariant Verification & Benchmarks

The test suite validates 6 fundamental deobfuscation invariants:

```bash
python -m unittest discover -s tests -v
```

### Invariant Test Results:
```text
test_bootstrap_set_chain (test_deobfuscator.TestBatchDeobfuscator) ... ok
test_builtin_env_negative_slicing (test_deobfuscator.TestBatchDeobfuscator) ... ok
test_caret_escaping_outside_quotes (test_deobfuscator.TestBatchDeobfuscator) ... ok
test_empty_quote_concatenation (test_deobfuscator.TestBatchDeobfuscator) ... ok
test_environment_variable_slicing (test_deobfuscator.TestBatchDeobfuscator) ... ok
test_string_substitution (test_deobfuscator.TestBatchDeobfuscator) ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.002s

OK
```

---

## 📁 Repository Architecture

```text
cmd-ast-deobfuscator/
├── .github/
│   └── workflows/
│       └── ci.yml                     # Automated GitHub Actions test workflow
├── docs/
│   ├── assets/
│   │   └── locales/                   # 10 localized dark terminal SVG banners
│   │       ├── en/banner.svg
│   │       ├── ko/banner.svg
│   │       └── ...
│   ├── locales/                       # 9 localized README documentation files
│   │   ├── ko.md
│   │   ├── zh-CN.md
│   │   └── ...
│   ├── BATCH_OBFUSCATION_DEEP_REVERSE_ENGINEERING_ANALYSIS.md
│   ├── BATCH_OBFUSCATION_ENCYCLOPEDIA.md
│   ├── CLASSIC_TO_MODERN_EVOLUTION.md
│   ├── BATCLOAK_SCRUBCRYPT_DEEP_DIVE.md
│   └── HUGGINGFACE_AI_MODELS_AND_DATASETS.md
├── references/
│   ├── references_index.json          # Index of 41 curated GitHub repositories
│   ├── huggingface-ai/                # 13 Hugging Face models & datasets
│   └── source-dissections/            # Line-by-line analyses of 7 open-source tools
├── rules/
│   ├── sigma_batch_obfuscation.yml    # Enterprise Sigma detection rule
│   └── yara_batch_obfuscation.yar     # YARA malware identification signatures
├── samples/                           # Obfuscated samples & verified clean counterparts
├── src/
│   └── deobfuscator_engine.py         # 6-Pass Static AST Evaluation Engine
├── tests/
│   └── test_deobfuscator.py           # Invariant test suite
├── LICENSE                            # MIT License
└── README.md                          # Primary English Documentation
```

---

## ⚖️ License & Responsible Disclosure

This project is licensed under the **MIT License** — see [`LICENSE`](LICENSE) for details.

> **Responsible Security Notice**: This software and associated research documentation are provided strictly for defensive security research, malware analysis, incident response, and academic education. All reverse engineering experiments were conducted within isolated offline sandbox environments.

<div align="center">
<sub>Engineered with precision by <strong>Maya Thorne</strong> · All rights reserved.</sub>
</div>
