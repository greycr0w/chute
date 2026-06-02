from __future__ import annotations

import os

from hypothesis import HealthCheck, settings

settings.register_profile(
    "chute",
    max_examples=200,
    deadline=None,
)
settings.register_profile(
    "ci-deep",
    max_examples=2000,
    stateful_step_count=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "chute"))
