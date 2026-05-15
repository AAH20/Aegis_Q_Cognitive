"""Autonomous recursive interrogation stack (AQC Sentinel).

This sub-package implements a **simulated** red-team feedback loop: a
Gymnasium environment models a JADC2 / BCI biometric transport surface
behind an ML-KEM-class gateway, and a lightweight tabular Q-learner
drives exploratory actions.  When learning plateaus, a **deterministic
``synthesize_new_zero_day``** step models what a code-synthesis / LLM
loop would do — mutating packetcraft heuristics so the agent can probe
novel DPI evasion paths.

This code is for **authorised continuous assurance** on systems you own.
It does not generate real Internet attacks, bind raw sockets, or ship
weaponised exploits.
"""

from __future__ import annotations

from .interrogation_ui import run_war_room
from .recursive_agent import InterrogationResult, RecursiveInterrogator
from .rl_environment import ACTION_NAMES, JADC2BioEnv

__all__ = [
    "ACTION_NAMES",
    "InterrogationResult",
    "JADC2BioEnv",
    "RecursiveInterrogator",
    "run_war_room",
]
