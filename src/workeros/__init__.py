"""Explicit local workers, descriptor handoff and optional managed release."""

from .original import (
    HandoffError, Identity, Observation, Original, ReadResult, Writer,
    observe, receive_original, send_original,
)
from .workers import Worker, WorkerRoster
from .custody import CustodyReceipt, CustodyRefused, IndependentCustody
from .managed import (
    DeliveryStatus, EffectStatus, PositionalWrite, ReleasePlan, ReleaseResult,
    release_executable,
)
from .supervisor import (
    CleanupResult, CleanupStatus, DirectChildSupervisor, LifecycleStatus,
    SupervisionResult, SupervisionStartError,
)

__all__ = [
    "HandoffError", "Identity", "Observation", "Original", "ReadResult", "Writer",
    "Worker", "WorkerRoster", "observe", "receive_original", "send_original",
    "CustodyReceipt", "CustodyRefused", "IndependentCustody", "DeliveryStatus",
    "EffectStatus", "PositionalWrite", "ReleasePlan", "ReleaseResult",
    "release_executable", "CleanupResult", "CleanupStatus", "DirectChildSupervisor",
    "LifecycleStatus", "SupervisionResult", "SupervisionStartError",
]
