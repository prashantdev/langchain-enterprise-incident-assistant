# Runbook 201: Admin Credentials & Account Escalation

## Overview
Procedures governing user account credential resets, password resets, and entitlement verification.

## Diagnostic Steps
1. Execute `getUserEntitlements` using the user's corporate email address.
2. Confirm user is active and belongs to an authorized department (e.g., `Engineering`, `DevOps`, `Support`, `HR`).

## Remediation Steps
1. Execute `resetUserPassword` passing the user's corporate email address.
2. Store temporary access token routing info and output confirmation details.
