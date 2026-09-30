# Runbook 101: Web & App Server Diagnostics

## Overview
Standard operating procedures for diagnosing web application server outages, service crashes, high memory consumption, and status verification.

## Diagnostic Steps
1. Execute `checkServerStatus` with the target server hostname (e.g., `web-prod-01`, `app-prod-02`).
2. Verify CPU and Memory utilization. If Memory > 90% or operational status is `CRASHED`, proceed to resolution step.

## Remediation Steps
1. Execute `restartService` passing the service name (e.g., `payment-service`, `web-gateway`) and server hostname.
2. Confirm service status returns `RUNNING` after restart.
3. Emit resolution notification.
