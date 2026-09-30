import logging
import requests
from typing import List, Optional, Any
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

logger = logging.getLogger("agent.llm_factory")

OLLAMA_CLASS_IDENTIFIER = "ollama"
OPENAI_CLASS_IDENTIFIER = "openai"
DEFAULT_OPENAI_KEY = "dummy-key"
HTTP_TIMEOUT_SECONDS = 2.0


class GenericLangChainChatModel(BaseChatModel):
    """LangChain BaseChatModel implementation making real outgoing HTTP LLM requests."""

    model_name: str
    base_url: str
    model_class: str
    api_key: str

    def _generate(self, messages: List[BaseMessage], stop: Optional[List[str]] = None, **kwargs: Any) -> ChatResult:
        prompt_text = messages[-1].content if messages else ""
        clean_url = self.base_url.rstrip("/")
        class_lower = self.model_class.lower()

        response_text = ""

        if OPENAI_CLASS_IDENTIFIER in class_lower:
            endpoint = f"{clean_url}/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key if self.api_key else DEFAULT_OPENAI_KEY}"
            }
            payload = {
                "model": self.model_name,
                "messages": [{"role": "user", "content": prompt_text}]
            }
            log_msg = f"[LLM OUTGOING REQUEST] OpenAI Chat API call to {endpoint} (model={self.model_name})"
            print(log_msg, flush=True)
            logger.info(log_msg)
            try:
                resp = requests.post(endpoint, json=payload, headers=headers, timeout=HTTP_TIMEOUT_SECONDS)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices:
                        response_text = choices[0].get("message", {}).get("content", "")
                else:
                    response_text = f"HTTP Error {resp.status_code}: {resp.text}"
            except Exception as exc:
                err_msg = f"[LLM OUTGOING REQUEST FAILED] Call to {endpoint} failed: {exc}"
                print(err_msg, flush=True)
                logger.warning(err_msg)
                response_text = f"LLM Call Failed: {exc}"
        else:
            endpoint = f"{clean_url}/api/generate"
            payload = {
                "model": self.model_name,
                "prompt": prompt_text,
                "stream": False
            }
            log_msg = f"[LLM OUTGOING REQUEST] Ollama API call to {endpoint} (model={self.model_name})"
            print(log_msg, flush=True)
            logger.info(log_msg)
            try:
                resp = requests.post(endpoint, json=payload, timeout=HTTP_TIMEOUT_SECONDS)
                if resp.status_code == 200:
                    response_text = resp.json().get("response", "")
                else:
                    response_text = f"HTTP Error {resp.status_code}: {resp.text}"
            except Exception as exc:
                err_msg = f"[LLM OUTGOING REQUEST FAILED] Call to {endpoint} failed: {exc}"
                print(err_msg, flush=True)
                logger.warning(err_msg)
                response_text = f"LLM Call Failed: {exc}"

        ai_message = AIMessage(content=response_text)
        generation = ChatGeneration(message=ai_message)
        return ChatResult(generations=[generation])

    @property
    def _llm_type(self) -> str:
        return "langchain-generic-chat-model"


class LLMFactory:
    """Factory for instantiating LangChain ChatModels."""

    @staticmethod
    def create_chat_model(model_name: str, base_url: str, model_class: str, api_key: str) -> BaseChatModel:
        logger.info(f"Creating LangChain ChatModel: name={model_name}, class={model_class}, base_url={base_url}")
        return GenericLangChainChatModel(
            model_name=model_name,
            base_url=base_url,
            model_class=model_class,
            api_key=api_key
        )
