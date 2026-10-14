# Enterprise IT Incident & Service Desk Assistant

Enterprise IT Incident & Service Desk Assistant built with FastAPI, LangChain, and ChromaDB.

## Overview

The incident assistant automates enterprise IT service desk operations including:
- **Triage Agent:** Analyzes incoming ticket requests, determines urgency/severity (P1-P4), extracts entities, and delegates remediation actions.
- **Remediation Agent:** Consults local standard operating procedures and runbooks from the Knowledge Base (KB) to recommend and execute remediation tools (e.g. server restarts, cache flushes, password resets).
- **Knowledge Base (KB):** In-memory ChromaDB vector store indexing IT incident runbooks with deterministic embeddings and metadata filtering.
- **Authentication & RBAC:** JWT authentication with role-based and department-based authorization checks.

## Installation

Using `pip` with `pyproject.toml`:

```bash
# Editable install
pip install -e .

# With dev dependencies (pytest, pytest-cov)
pip install -e ".[dev]"
```

## Running the Server

Start the FastAPI embedded server:

```bash
./startserver.sh
```

Or run directly using the CLI entrypoint:

```bash
incident-assistant
```

## Running Tests

Run unit and integration tests:

```bash
./runtests.sh
```

Run security test suites:

```bash
# Basic security tests (unhardened master)
./run-security-suite.sh --suite basic

# Internal security guardrail tests (hardened secured3)
./run-security-suite.sh --suite guardrail
```
