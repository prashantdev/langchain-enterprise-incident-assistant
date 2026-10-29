# Enterprise IT Incident & Service Desk Assistant

> **Official Demonstrator for [langchain-security-extension](https://github.com/prashantdev/langchain-security-extension/)**

A production-style IT Incident & Service Desk Assistant built with **FastAPI**, **LangChain**, and **ChromaDB**. This repository demonstrates the security vulnerabilities of standard LLM agents and how **[langchain-security-extension](https://github.com/prashantdev/langchain-security-extension/)** resolves them using deterministic, code-level Policy Enforcement Points (PEPs).

## Branch Comparison: Unhardened vs. Secured

This repository maintains two branches to contrast standard prompt-based security against deterministic enforcement:

| Branch | Description | `basic` Suite (15 tests) | `guardrail` Suite (31 exploit vectors) |
| :--- | :--- | :---: | :---: |
| **`main`** | **Unhardened Baseline:** Standard LangChain agents with HTTP JWT auth. Vulnerable to prompt injection, argument manipulation, RAG clearance leaks, and runaway loops. | ✅ Passes | ❌ Fails |
| **`secured`** | **Hardened with `langchain-security-extension`:** Enforces `@secured_tool` bytecode PEPs, CEL parameter rules, Schema Hiding, Secure RAG (AST pre-filters + HMAC envelopes), in-flight DLP, retry budgets, and async SIEM audit streaming. | ✅ Passes | ✅ Passes |

> 📖 **[Read the Hands-On Quickstart Walkthrough](https://prashantdev.github.io/langchain-security-extension/guides/0.%20Quickstart%20Walkthrough.html)** for a step-by-step tour comparing test runs and inspecting payloads.

## What the Assistant Does

- **Triage Agent:** Classifies incoming tickets (P1–P4), extracts target entities, and delegates remediation.
- **Remediation Agent:** Queries standard operating procedures (SOPs) and executes infrastructure tools (`restart_server`, `flush_cache`, `reset_password`, `block_ip`).
- **Knowledge Base (RAG):** In-memory ChromaDB store indexing IT incident runbooks.
- **Identity & RBAC:** JWT authentication propagating caller identity (`SecurityIdentity`) through LangChain's `RunnableConfig`.

## Quickstart

### 1. Installation

```bash
pip install -e ".[dev]"
```

*(On the `secured` branch, also install [langchain-security-extension](https://github.com/prashantdev/langchain-security-extension/).)*

### 2. Run the Server

```bash
./startserver.sh
```

*(Server and security settings are configured in `config.properties`. See the [Unified Configuration Reference](https://prashantdev.github.io/langchain-security-extension/guides/13.%20Configuration%20Reference.html) for all property definitions and environment variable overrides.)*

### 3. Run Tests

```bash
# Unit & integration tests
./runtests.sh

# Baseline functional & auth security tests (passes on main and secured)
./run-security-suite.sh --suite basic

# 31 adversarial exploit & guardrail tests (fails on main, passes on secured)
./run-security-suite.sh --suite guardrail
```

## License

Apache 2.0
