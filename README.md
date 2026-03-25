# BYU CS 465 — Computer Security

Course projects from **CS 465: Computer Security** at Brigham Young University,
taught by **Professor Daniel Zappala** during **Fall 2025**.

---

## Course Overview

CS 465 provides a broad introduction to computer security, helping students think
like both attackers and defenders. Topics include software vulnerabilities and
exploitation, cryptography, secure software development in Rust, password security,
operating system security, network security, and threat modeling.

- **Institution:** Brigham Young University (BYU), Provo, UT
- **Term:** Fall 2025
- **Instructor:** Professor Daniel Zappala
- **Languages:** C, Rust

---

## Projects

### `cracking-password-vaults`

A hands-on exploration of password security and hash cracking. Includes practice
exercises and a breach scenario in which real (simulated) password vault data is
attacked using techniques such as dictionary attacks and hash reversal.

**Key directories:**
- `src/` — Rust source code for cracking tools
- `practice/` — Practice exercises and warm-up challenges
- `breach/` — The main breach/cracking scenario

---

### `encrypted-communication`

Implementation of a secure encrypted communication system in Rust. Applies
cryptographic primitives (symmetric encryption, MACs, key exchange) to build
a system where two parties can communicate confidentially and with integrity.
Developed inside a Dev Container for a consistent Linux environment.

**Key directories:**
- `src/` — Rust source code for the encrypted communication protocol
- `binaries/` — Pre-compiled binaries (used in the project handout)
- `.devcontainer/` — Docker-based development container configuration

---

### `exploit_and_patch`

A software security project focused on finding, exploiting, and then patching
real vulnerabilities in C programs. Covers common vulnerability classes such as
buffer overflows and memory corruption, demonstrating how attackers exploit flawed
code and how developers can fix it.

**Key directories:**
- `src/` — Vulnerable C programs and exploit code
- `handout/` — Project specification and supporting materials

---

### `rustlings`

Completed [Rustlings](https://github.com/rust-lang/rustlings) exercises — a
collection of small Rust programs used to learn the language. Assigned as
preparation for the security projects that use Rust for safe systems programming.

**Key directories:**
- `exercises/` — Rustlings exercise files (completed)
- `solutions/` — Reference solutions

---

## Repository Structure

```
byu-cs465/
├── cracking-password-vaults/   # Password hash cracking project
├── encrypted-communication/    # Secure communication in Rust
├── exploit_and_patch/          # Vulnerability exploitation and patching in C
└── rustlings/                  # Rust language learning exercises
```

---

## License

This project is licensed under the [MIT License](LICENSE).
