# ⚡ VORTEX

### Python Code Protection & Obfuscation Engine

VORTEX is a Python code transformation and protection tool designed to make Python source code harder to analyze, reverse-engineer, and modify.

It combines AST-based transformations with optional anti-debugging, bytecode processing, and verification stages.

---

## ✨ Features

- 🌀 AST-based code obfuscation
- 🛡️ Anti-debugging support
- 🧬 Bytecode transformation
- ✅ Output verification
- 📊 Build statistics
- 🚀 Configurable protection pipeline

---

## 📦 Installation

```bash
git clone https://github.com/mohammadamin1337/VORTEX.git
cd VORTEX
python3 --version
```

> **Recommended:** Python 3.10+

---

## 🚀 Usage

Basic:

```bash
python3 vortex.py 1.py
```

Anti-debugging:

```bash
python3 vortex.py 1.py --anti-debug
```

Bytecode processing:

```bash
python3 vortex.py 1.py --bytecode
```

Verification:

```bash
python3 vortex.py 1.py --verify
```

Statistics:

```bash
python3 vortex.py 1.py --stats
```

### 🔥 Full Protection Pipeline

```bash
python3 vortex.py 1.py --anti-debug --bytecode --verify --stats
```

Example output:

```text
[*] VORTEX  →  1.py
[*] AST transformation complete
[*] Anti-debugging enabled
[*] Bytecode transformation enabled
[*] Verification passed
[*] Statistics generated
[+] Protection completed successfully
```

---

## 🧠 Pipeline

```text
┌──────────────────┐
│   Python Source  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│    AST Parsing   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ AST Transformation│
└────────┬─────────┘
         │
    ┌────┴─────┐
    ▼          ▼
┌─────────┐ ┌────────────┐
│Obfuscate│ │ Anti-Debug │
└────┬────┘ └──────┬─────┘
     │              │
     └──────┬───────┘
            ▼
┌──────────────────┐
│ Bytecode Layer   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│    Verification  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Protected Output │
└──────────────────┘
```

---

## 🛠️ Command Options

| Option | Description |
|---|---|
| `--anti-debug` | Enable anti-debugging transformations |
| `--bytecode` | Enable bytecode-level processing |
| `--verify` | Verify generated output |
| `--stats` | Display transformation statistics |

---

## 📁 Example

Input:

```python
def hello(name):
    message = f"Hello, {name}!"
    print(message)

hello("World")
```

Run:

```bash
python3 vortex.py example.py --anti-debug --bytecode --verify --stats
```

VORTEX processes the source through the configured transformation pipeline and generates the protected output.

---

## ⚠️ Disclaimer

VORTEX is an **obfuscation/protection tool**, not an encryption system.

Obfuscation can make reverse engineering more difficult, but it cannot guarantee that Python code is impossible to recover or analyze.

Do not embed secrets such as API keys, passwords, private tokens, or credentials directly in distributed Python source code.

Use VORTEX only on software you own or are authorized to protect.

---

## 🧪 Verification

```bash
python3 vortex.py target.py --verify
```

It is recommended to test protected output in an isolated environment before deployment.

---

## 🔧 Development

Bug reports and pull requests are welcome.

When reporting an issue, include:

1. Python version
2. VORTEX version or commit
3. Minimal reproducible input
4. Full error message
5. Command used

---

## 📜 License

Add your preferred license to the repository.

Example:

```text
MIT License
```

---

<div align="center">

## ⚡ VORTEX

**Transform · Protect · Verify**

Made with 🐍 Python by [mohammadamin1337](https://github.com/mohammadamin1337)

</div>
