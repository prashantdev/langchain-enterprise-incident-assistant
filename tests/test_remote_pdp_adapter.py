"""Unit tests for RemotePDPAdapter OPA integration and circuit breaker fallback."""

from app.security.user_registry import UserRegistry
from app.security.security_integration import (
    get_remote_pdp_adapter,
    security_identity_from_context,
)
from langchain_security_extension.security_core.identity import IdentityBridge
from langchain_security_extension.security_core.pdp import PolicyRequest
from langchain_security_extension.security_core.constants import ACTION_TOOL_EXECUTE
from langchain_security_extension.security_pdp_opa.opa_adapter import CircuitBreakerState


def test_remote_pdp_adapter_circuit_breaker():
    adapter = get_remote_pdp_adapter(failure_threshold=1, recovery_seconds=0.0)
    assert adapter.circuit_state == CircuitBreakerState.CLOSED

    registry = UserRegistry()
    sec_ctx = registry.build_security_context("alex.devops@enterprise.com")
    sec_id = security_identity_from_context(sec_ctx)
    cfg = IdentityBridge.create_runnable_config(sec_id)

    opa_req = PolicyRequest.create(
        subject=sec_id,
        action=ACTION_TOOL_EXECUTE,
        resource={
            "name": "restart_service",
            "target_id": "restart_service",
            "tenant_id": sec_id.tenant_id,
            "required_roles": [],
            "min_clearance": 1,
            "cel_expression": "",
            "is_mutative": True,
            "arguments": {"service_name": "payment-service", "server_name": "web-prod-01"},
        },
        context={"config": cfg},
    )
    decision = adapter.evaluate(opa_req)
    assert decision.is_permitted is False
    assert adapter.circuit_state in (CircuitBreakerState.OPEN, CircuitBreakerState.HALF_OPEN)
