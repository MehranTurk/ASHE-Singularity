# A.S.H.E v5.0 - The Singularity 🛡️🚀
### **Autonomous Self-Healing Exploit Framework**

A.S.H.E (Advanced Self-Healing Exploit) is a professional-grade security framework designed for automated vulnerability research and exploitation on Linux systems. Unlike traditional, static exploit scripts, A.S.H.E is an **Adaptive Engine** that analyzes binary protections and server behavior in real-time to reconstruct payloads on the fly.

---

## 🌟 Key Features

* **Self-Healing Offset Discovery:** Automatically identifies the exact stack overflow offset using heuristic core-dump analysis or remote side-channel probing.
* **Universal Protection Bypass:** Intelligently detects and bypasses modern security mitigations, including **NX (No-Execute)** and **ASLR**, using automated **Ret2Libc** and **ROP** chains.
* **Blind ROP (BROP) Engine:** Capable of attacking remote targets without access to the original binary file. It reconstructs the exploit path purely through crash analysis.
* **Advanced BROP Gadget Scanner:** Implements a sophisticated memory scanner to locate critical "Stop Gadgets" and "Pop 6 Registers" gadgets (e.g., in `__libc_csu_init`) to gain full register control.
* **Multi-Vector Input Detection:** Seamlessly detects whether the vulnerability is triggered via `Standard Input (stdin)` or `Command Line Arguments (argv)`.
* **Unpredictable Payload Generation:** Features polymorphic padding and randomized timing to evade basic IDS/IPS detection patterns.
* **Intelligent Stack Alignment:** Automatically handles the 16-byte stack alignment requirement for `system()` calls on modern x64 Linux distributions.

---

## 🛠️ Technical Architecture

The framework operates through a high-intelligence lifecycle:
1.  **Phase 1 - Reconnaissance:** Dynamic detection of stack depth, architecture (x86/x64), and security markers (PIE, NX, Canary).
2.  **Phase 2 - Memory Mapping (BROP):** Probing remote memory to map out "safe" addresses (Stop Gadgets) and "control" gadgets.
3.  **Phase 3 - Information Leak:** Using ROP primitives (like `puts` or `printf`) to leak GOT entries and calculate the real-time address of `libc`.
4.  **Phase 4 - Final Strike:** Constructing and deploying a localized payload to spawn a shell (`/bin/sh`).

---

## 🚀 Installation & Setup

Designed and optimized for **Kali Linux**.

### Quick Install
Simply run the provided installation script:
```bash
chmod +x install.sh
sudo ./install.sh
```

### Manual Prerequisites
```bash
pip install --upgrade pwntools
```

### System Tuning
For optimal self-healing performance, enable unlimited core dumps on your pentest machine:
```bash
ulimit -c unlimited
echo "core" | sudo tee /proc/sys/kernel/core_pattern
```

---

## 💻 Usage

### 1. Standard Local Exploitation
```bash
python3 ashe.py --binary ./vulnerable_bin
```

### 2. Remote Target (with Binary)
```bash
python3 ashe.py --binary ./target_bin --remote 192.168.1.50:4444
```

### 3. Blind ROP Attack (No Binary Access)
```bash
python3 ashe.py --target 10.10.10.5 --port 1337
```

---

## 📋 Example Recon Report
```text
--- [ FINAL RECON REPORT ] ---
Target: 192.168.1.100:1337
Vulnerability: Stack Overflow
Offset: 72 Bytes
Stop Gadget: 0x4006b0
BROP Gadget: 0x40074a (pop rbx, rbp, r12, r13, r14, r15; ret)
Exploit Strategy: Ret2Libc (Bypass NX/ASLR)
--- [ END OF REPORT ] ---
```

---

## ⚖️ Legal Disclaimer

**Author: Mehran (Security Researcher)**

This tool is intended **strictly for educational purposes** and authorized professional penetration testing. Attacking targets without prior written consent is illegal and punishable by law. The developer assumes no liability for any misuse, damage, or legal consequences resulting from the use of this framework. Use responsibly and legally.