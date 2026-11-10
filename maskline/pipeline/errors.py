"""Pipeline-specific exceptions."""

from __future__ import annotations

from ..utils import MasklineError


class PipelineError(MasklineError):
    pass


class PipelineInterrupted(PipelineError):

    def __init__(self, run_id: str) -> None:
        super().__init__(f"run {run_id} interrupted at a batch checkpoint; use resume")
        self.run_id = run_id
