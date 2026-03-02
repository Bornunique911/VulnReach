from abc import ABC, abstractmethod

from .models import AgentResult, ScanContext


class BaseTool(ABC):
    tool_name: str

    @abstractmethod
    async def run(self, context: ScanContext) -> AgentResult:
        raise NotImplementedError


class BaseAgent(ABC):
    """Interface for all scanning agents."""

    tool_name: str

    @abstractmethod
    async def run(self, context: ScanContext) -> AgentResult:
        """Execute the agent with the provided scan context."""
        raise NotImplementedError
