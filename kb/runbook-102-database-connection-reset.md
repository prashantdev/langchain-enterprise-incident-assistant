# Runbook 102: Database Connection Reset

## Overview
Procedures for handling database pool exhaustion, connection timeouts, and database service verification before issuing restarts.

## Diagnostic Steps
1. Execute `checkServerStatus` for target database server hostname (e.g., `db-prod-01`).
2. Verify active connections and connection pool status.

## Remediation Steps
1. If pool is exhausted or state is degraded, execute `restartService` for service `db-connection-pool` or `postgresql-service`.
2. Re-verify server status.
