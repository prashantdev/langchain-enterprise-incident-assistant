from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from security_core.identity import SecurityIdentity

from app.security.master_data import (
    DEFAULT_TENANT_ID,
    CLEARANCE_UNAUTHENTICATED,
    CLEARANCE_STANDARD,
    CLEARANCE_ORDER,
)


class SecurityContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    userEmail: str
    department: str
    assignedRoles: List[str] = Field(default_factory=list)
    clearanceLevel: str = CLEARANCE_UNAUTHENTICATED
    tenantId: str = DEFAULT_TENANT_ID
    traceId: Optional[str] = None
    spanId: Optional[str] = None
    securityIdentity: Optional[SecurityIdentity] = Field(default=None, exclude=True)

    @classmethod
    def from_identity(cls, identity: SecurityIdentity, clearance_label: Optional[str] = None) -> "SecurityContext":
        """Construct SecurityContext directly from a verified library SecurityIdentity envelope."""
        roles_list = list(identity.roles)
        if clearance_label is None:
            idx = min(max(identity.clearance_level, 0), len(CLEARANCE_ORDER) - 1)
            clearance_label = CLEARANCE_ORDER[idx]
        attrs = identity.attributes
        return cls(
            userEmail=identity.subject_id,
            department=identity.department_id,
            assignedRoles=roles_list,
            clearanceLevel=clearance_label,
            tenantId=identity.tenant_id,
            traceId=attrs.get("trace_id"),
            spanId=attrs.get("span_id"),
            securityIdentity=identity,
        )

    def to_identity(self, clearance_rank_map: Dict[str, int], default_clearance: int) -> SecurityIdentity:
        """Return the bound SecurityIdentity directly, avoiding redundant claims parsing."""
        if self.securityIdentity is not None:
            if (self.traceId and self.securityIdentity.attributes.get("trace_id") != self.traceId) or (
                self.spanId and self.securityIdentity.attributes.get("span_id") != self.spanId
            ):
                self.securityIdentity = self.securityIdentity.with_trace_context(self.traceId, self.spanId)
            return self.securityIdentity

        raw_clr = self.clearanceLevel
        if isinstance(raw_clr, str) and raw_clr.isdigit():
            clr_rank = int(raw_clr)
        else:
            clr_rank = clearance_rank_map.get(str(raw_clr).upper(), default_clearance)

        attrs: Dict[str, Any] = {}
        if self.traceId:
            attrs["trace_id"] = self.traceId
        if self.spanId:
            attrs["span_id"] = self.spanId

        self.securityIdentity = SecurityIdentity.create(
            subject_id=self.userEmail,
            tenant_id=self.tenantId,
            roles=set(self.assignedRoles),
            clearance_level=clr_rank,
            department_id=self.department,
            attributes=attrs,
        )
        return self.securityIdentity


class User(BaseModel):
    email: str
    name: str
    department: str
    roles: List[str] = Field(default_factory=list)
    clearanceLevel: str = CLEARANCE_STANDARD
    password: Optional[str] = None


class TicketRequest(BaseModel):
    ticketId: Optional[str] = None
    userEmail: str
    rawTicketText: str
    submittedAt: Optional[str] = None
    securityContext: Optional[SecurityContext] = None


class IncidentContext(BaseModel):
    ticketId: str
    userEmail: str
    rawTicketText: str
    priority: str
    targetServer: Optional[str] = None
    targetService: Optional[str] = None
    department: str = "UNKNOWN"
    triageStatus: Optional[str] = "SUCCESS_LLM"
    entities: Dict[str, str] = Field(default_factory=dict)
    securityContext: Optional[SecurityContext] = None


class RemediationReport(BaseModel):
    ticketId: str
    rootCause: Optional[str] = None
    actionsTaken: List[str] = Field(default_factory=list)
    finalStatus: str
    userFacingResolutionMessage: str
    stageResults: Dict[str, str] = Field(default_factory=dict)

    def add_stage_result(self, stage: str, status: str) -> None:
        self.stageResults[stage] = status

    @classmethod
    def manual_intervention(cls, ticket_id: str) -> "RemediationReport":
        return cls(
            ticketId=ticket_id,
            rootCause="Pending Manual Investigation",
            actionsTaken=[
                "Logged ticket request into Service Desk queue",
                "Emitted manual intervention notice to IT Operations team"
            ],
            finalStatus="MANUAL_INTERVENTION_REQUIRED",
            userFacingResolutionMessage="Ticket request received; IT operations team has been notified to investigate and resolve this request manually.",
            stageResults={
                "remediation_security": "SKIPPED (NO_POLICY_ENGINE)",
                "remediation_execution": "FALLBACK_MANUAL",
                "rag_clearance": "UNCHECKED (Standard Retriever)"
            }
        )


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
