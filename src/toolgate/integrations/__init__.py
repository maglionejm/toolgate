"""Framework adapters: turn a grant's reachable tools into framework-native
tool objects. All adapters are driven by the gate's discovery endpoint
(GET /v1/gate/tools) — one delegation, every framework."""

from .anthropic import anthropic_tools
from .langchain import langchain_tools
from .openai import openai_tools

__all__ = ["anthropic_tools", "langchain_tools", "openai_tools"]
