import os
from pathlib import Path
from typing import Dict, Optional

DEFAULT_SERVER_HOST = "0.0.0.0"
DEFAULT_SERVER_PORT = 7070
DEFAULT_CONFIG_FILE = "config.properties"
DEFAULT_JWT_SECRET = "secret-key"

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

    def __init__(self, config_file_path: Optional[str] = None):
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


config = AppConfig()
