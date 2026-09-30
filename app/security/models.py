from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime

DEFAULT_TENANT_ID = "tenant-default"
UNAUTHENTICATED_CLEARANCE = "UNAUTHENTICATED"
DEFAULT_CLEARANCE_STANDARD = "STANDARD"


class SecurityContext(BaseModel):
    userEmail: str
    department: str
    assignedRoles: List[str] = Field(default_factory=list)
    clearanceLevel: str = UNAUTHENTICATED_CLEARANCE
    tenantId: str = DEFAULT_TENANT_ID


class User(BaseModel):
    email: str
    name: str
    department: str
    roles: List[str] = Field(default_factory=list)
    clearanceLevel: str = DEFAULT_CLEARANCE_STANDARD
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
