from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class LLMProvider(ABC):
    @abstractmethod
    async def complete(self, system_prompt: str, user_message: str, **kwargs: Any) -> str:
        ...

    @abstractmethod
    async def complete_json(
        self, system_prompt: str, user_message: str, schema: dict
    ) -> Any:
        ...
