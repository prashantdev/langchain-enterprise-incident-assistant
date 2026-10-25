import os
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_SERVER_HOST = "0.0.0.0"
DEFAULT_SERVER_PORT = 7070
DEFAULT_CONFIG_FILE = "config.properties"
DEFAULT_JWT_SECRET = "secret-key"
DEFAULT_SECURITY_HMAC_SECRET = "enterprise-hmac-secret-key"
DEFAULT_TENANT_ID = "CORP_MAIN"
DEFAULT_DEPARTMENT_ID = "IT_OPS"
DEFAULT_OVERSAMPLING_FACTOR = 3.0

DEFAULT_PDP_MODE = "EMBEDDED"
DEFAULT_PDP_OPA_URL = "http://localhost:8181/v1/data/langchain/security/allow"
DEFAULT_PDP_OPA_TIMEOUT = 0.05
DEFAULT_PDP_CB_THRESHOLD = 1
DEFAULT_PDP_CB_RECOVERY = 30.0

DEFAULT_CACHE_L1_ENABLED = "true"
DEFAULT_CACHE_L2_ENABLED = "true"
DEFAULT_CACHE_L2_TTL = 60.0
DEFAULT_CACHE_L2_MAX_ENTRIES = 1000

DEFAULT_INGESTION_MODE = "STRICT_FAIL_CLOSED"
DEFAULT_RETRY_MAX_VIOLATIONS = 3
DEFAULT_ABUSE_WINDOW_SECONDS = 60.0
DEFAULT_ABUSE_MAX_DENIALS = 3

DEFAULT_SPLUNK_HEC_URL = ""
DEFAULT_SPLUNK_TOKEN = ""
DEFAULT_PII_REDACTION_SCOPE = "audit_only"

DEFAULT_CHROMA_URL = "http://localhost:8000"
DEFAULT_CHROMA_COLLECTION = "it_runbooks"
DEFAULT_EMBEDDING_MODEL = "AllMiniLmL6V2"

DEFAULT_MODEL1_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL1_NAME = "qwen-nothink"
DEFAULT_MODEL1_CLASS = "ollama"
DEFAULT_MODEL1_API_KEY = ""
DEFAULT_MODEL1_TIMEOUT = "300s"

DEFAULT_MODEL2_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
DEFAULT_MODEL2_NAME = "gemini-3.5-flash"
DEFAULT_MODEL2_CLASS = "openai"
DEFAULT_MODEL2_API_KEY = ""
DEFAULT_MODEL2_TIMEOUT = "60s"


class AppConfig:
    """Application configuration loader reading config.properties and environment variables."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        config_file_path: Optional[str] = args[0] if len(args) > 0 else kwargs.get("config_file_path")
        if config_file_path is None:
            config_file_path = DEFAULT_CONFIG_FILE
        self.config_path = Path(config_file_path)
        self.properties: Dict[str, str] = {}
        self._load_properties()

    def _load_properties(self) -> None:
        if self.config_path.exists():
            with open(self.config_path, "r", encoding="utf-8") as file:
                for line in file:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if "=" in stripped:
                        key, val = stripped.split("=", 1)
                        self.properties[key.strip()] = val.strip()

    def get_property(self, key: str, default_value: str) -> str:
        env_key = key.upper().replace(".", "_")
        if env_key in os.environ:
            return os.environ[env_key]
        return self.properties.get(key, default_value)

    @property
    def server_host(self) -> str:
        return self.get_property("server.host", DEFAULT_SERVER_HOST)

    @property
    def server_port(self) -> int:
        port_str = self.get_property("server.port", str(DEFAULT_SERVER_PORT))
        return int(port_str)

    @property
    def chroma_url(self) -> str:
        return self.get_property("chroma.url", DEFAULT_CHROMA_URL)

    @property
    def chroma_collection(self) -> str:
        return self.get_property("chroma.collection", DEFAULT_CHROMA_COLLECTION)

    @property
    def embedding_model_name(self) -> str:
        return self.get_property("embedding.model.name", DEFAULT_EMBEDDING_MODEL)

    @property
    def model1_base_url(self) -> str:
        return self.get_property("model1.baseUrl", DEFAULT_MODEL1_BASE_URL)

    @property
    def model1_name(self) -> str:
        return self.get_property("model1.modelname", DEFAULT_MODEL1_NAME)

    @property
    def model1_class(self) -> str:
        return self.get_property("model1.modelclass", DEFAULT_MODEL1_CLASS)

    @property
    def model1_api_key(self) -> str:
        return self.get_property("model1.apikey", DEFAULT_MODEL1_API_KEY)

    @property
    def model2_base_url(self) -> str:
        return self.get_property("model2.baseUrl", DEFAULT_MODEL2_BASE_URL)

    @property
    def model2_name(self) -> str:
        return self.get_property("model2.modelname", DEFAULT_MODEL2_NAME)

    @property
    def model2_class(self) -> str:
        return self.get_property("model2.modelclass", DEFAULT_MODEL2_CLASS)

    @property
    def model2_api_key(self) -> str:
        return self.get_property("model2.apikey", DEFAULT_MODEL2_API_KEY)

    @property
    def jwt_secret(self) -> str:
        return self.get_property("jwt.secret", DEFAULT_JWT_SECRET)

    @property
    def security_hmac_secret(self) -> str:
        return self.get_property("security.hmac.secret", DEFAULT_SECURITY_HMAC_SECRET)

    @property
    def default_tenant_id(self) -> str:
        return self.get_property("security.default.tenant", DEFAULT_TENANT_ID)

    @property
    def default_department_id(self) -> str:
        return self.get_property("security.default.department", DEFAULT_DEPARTMENT_ID)

    @property
    def default_oversampling_factor(self) -> float:
        val_str = self.get_property("security.retriever.oversampling", str(DEFAULT_OVERSAMPLING_FACTOR))
        return float(val_str)

    @property
    def pdp_mode(self) -> str:
        return self.get_property("security.pdp.mode", DEFAULT_PDP_MODE)

    @property
    def pdp_opa_url(self) -> str:
        return self.get_property("security.pdp.opa.url", DEFAULT_PDP_OPA_URL)

    @property
    def pdp_opa_timeout_seconds(self) -> float:
        return float(self.get_property("security.pdp.opa.timeout", str(DEFAULT_PDP_OPA_TIMEOUT)))

    @property
    def pdp_circuit_breaker_threshold(self) -> int:
        return int(self.get_property("security.pdp.circuitbreaker.threshold", str(DEFAULT_PDP_CB_THRESHOLD)))

    @property
    def pdp_circuit_breaker_recovery_seconds(self) -> float:
        return float(self.get_property("security.pdp.circuitbreaker.recovery", str(DEFAULT_PDP_CB_RECOVERY)))

    @property
    def cache_l1_enabled(self) -> bool:
        return self.get_property("security.cache.l1.enabled", DEFAULT_CACHE_L1_ENABLED).lower() == "true"

    @property
    def cache_l2_enabled(self) -> bool:
        return self.get_property("security.cache.l2.enabled", DEFAULT_CACHE_L2_ENABLED).lower() == "true"

    @property
    def cache_l2_ttl_seconds(self) -> float:
        return float(self.get_property("security.cache.l2.ttl", str(DEFAULT_CACHE_L2_TTL)))

    @property
    def cache_l2_max_entries(self) -> int:
        return int(self.get_property("security.cache.l2.maxEntries", str(DEFAULT_CACHE_L2_MAX_ENTRIES)))

    @property
    def ingestion_mode(self) -> str:
        return self.get_property("security.ingestion.mode", DEFAULT_INGESTION_MODE)

    @property
    def retry_max_violations(self) -> int:
        return int(self.get_property("security.retry.maxViolations", str(DEFAULT_RETRY_MAX_VIOLATIONS)))

    @property
    def abuse_window_seconds(self) -> float:
        return float(self.get_property("security.abuse.windowSeconds", str(DEFAULT_ABUSE_WINDOW_SECONDS)))

    @property
    def abuse_max_denials(self) -> int:
        return int(self.get_property("security.abuse.maxDenials", str(DEFAULT_ABUSE_MAX_DENIALS)))

    @property
    def splunk_hec_url(self) -> str:
        url = os.environ.get("SPLUNK_HEC_URL")
        if url:
            return url
        return self.get_property("security.audit.splunk.hec.url", DEFAULT_SPLUNK_HEC_URL)

    @property
    def splunk_token(self) -> str:
        token = os.environ.get("SPLUNK_TOKEN")
        if token:
            return token
        return self.get_property("security.audit.splunk.token", DEFAULT_SPLUNK_TOKEN)

    @property
    def pii_redaction_scope(self) -> str:
        return self.get_property("security.pii.redaction.scope", DEFAULT_PII_REDACTION_SCOPE)


config = AppConfig()

