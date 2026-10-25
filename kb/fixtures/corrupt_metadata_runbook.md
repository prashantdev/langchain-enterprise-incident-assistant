<!-- TEST FIXTURE: corrupt_metadata_runbook.md
     Purpose: Used for Guardrail Test 03 verification of strict fail-closed atomic batch rollback.
     Specification: 1. secure-ingestion-pipeline.md (§4 - Policy 1: Strict Fail-Closed Mode)
     This document carries a corrupt or tampered HMAC envelope hash to trigger validation failure.
-->
<!-- sec:envelope_hash=tampered_corrupt_hmac_signature_000000000000000000000000000000 -->
# Runbook 998: Corrupt Metadata Hardware Diagnostics

## Overview
Procedures for testing hardware failure diagnostics with tampered or corrupt security envelope metadata.

## Diagnostic Steps
1. Verify server chassis temperature sensors.
2. Check power supply status.
