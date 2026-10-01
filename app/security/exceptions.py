"""
Domain security exceptions for Enterprise IT Incident Assistant.
"""

from typing import Optional, Dict, Any


class SecurityAuthorizationError(Exception):
    """Base exception for security authorization failures in the application."""

    def __init__(self, message: str, diagnostic_reason: Optional[str], obligations: Optional[Dict[str, Any]]):
        super().__init__(message)
        self.message = message
        self.diagnostic_reason = diagnostic_reason
        self.obligations = obligations

    @classmethod
    def create(cls, message: str, diagnostic_reason: Optional[str], obligations: Optional[Dict[str, Any]]):
        return cls(message, diagnostic_reason, obligations)


class ToolEntityValidationError(SecurityAuthorizationError):
    """Exception raised when tool execution or parameter validation fails for target infrastructure entities."""

    def __init__(self, tool_name: str, message: str, diagnostic_reason: Optional[str]):
        super().__init__(message, diagnostic_reason, None)
        self.tool_name = tool_name

    @classmethod
    def for_tool(cls, tool_name: str, message: str, diagnostic_reason: Optional[str]):
        return cls(tool_name, message, diagnostic_reason)
