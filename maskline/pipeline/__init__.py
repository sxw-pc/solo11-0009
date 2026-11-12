"""Streaming execution pipeline."""

from .errors import PipelineError, PipelineInterrupted
from .runner import RunResult, execute_run
from .targets import OutputTarget, make_target, target_for_resume

__all__ = [
    "OutputTarget",
    "PipelineError",
    "PipelineInterrupted",
    "RunResult",
    "execute_run",
    "make_target",
    "target_for_resume",
]
