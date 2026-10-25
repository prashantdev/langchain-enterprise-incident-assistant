<!-- TEST FIXTURE: unlabelled_runbook.md
     Purpose: Used for Guardrail Test 07 and Test 04 verification of unlabelled document quarantine policies.
     Specification: 1. secure-ingestion-pipeline.md (§2 - Stage 4: SecurityEnvelopeValidator)
     This document contains valid operational content but intentionally lacks sec:* envelope metadata tags.
-->
# Runbook 999: Unlabelled Network Diagnostics

## Overview
This runbook contains unlabelled network diagnostic procedures for testing ingestion quarantine policies.
It lacks mandatory security metadata envelope attributes (sec:tenant_id, sec:classification_level, sec:allowed_roles).

## Diagnostic Steps
1. Execute ping diagnostics against internal gateway.
2. Check network route tables and interfaces.
