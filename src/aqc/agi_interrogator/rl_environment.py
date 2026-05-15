"""Gymnasium environment: simulated JADC2 / BCI transport vs PQC gateway.

Observation (normalised floats in ``[0, 1]``):

0. Path RTT / tactical latency (scaled 0–32 ms → 0–1).
1. Payload entropy proxy (Shannon-normalised).
2. ML-DSA / transcript verification confidence (1 = valid; 0 = rejected).
3. Gateway *block* flag from the last step (1 = blocked by ML-KEM/DPI).
4. Gateway *defence integrity* (1 = pristine, 0 = collapsed).

Actions (``Discrete(4)``):

0. ``mutate_payload`` — polymorphic EEG / neural frame mutation.
1. ``downgrade_cipher`` — attempt legacy/classical tunnel downgrade.
2. ``inject_8ms_jitter`` — timing side-channel / tactical latency stress.
3. ``spoof_eeg_wave`` — Soul Catcher 2.0-style brain-print replay / spoof.

Rewards follow the product brief: heavy penalty on ML-KEM block,
small per-step penalty to encourage brevity, large bonuses for the
cardiac / tactical DoS analogue (> 8 ms sustained excursion) and for
cognitive-channel bypass.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, SupportsFloat

import numpy as np

try:
    import gymnasium as gym  # type: ignore[import-untyped]
    from gymnasium import spaces  # type: ignore[import-untyped]
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "JADC2BioEnv requires gymnasium. Install with: pip install -e '.[agi]'"
    ) from e


ACTION_MUTATE_PAYLOAD = 0
ACTION_DOWNGRADE_CIPHER = 1
ACTION_INJECT_JITTER = 2
ACTION_SPOOF_EEG = 3

ACTION_NAMES: tuple[str, ...] = (
    "mutate_payload",
    "downgrade_cipher",
    "inject_8ms_jitter",
    "spoof_eeg_wave",
)


@dataclass
class EpisodeFlags:
    cardiac_exploit: bool = False
    soul_catcher_breach: bool = False


class JADC2BioEnv(gym.Env):
    """Simulated bio-telemetry interrogation surface (tabular RL friendly)."""

    metadata = {"render_modes": []}

    def __init__(
        self,
        *,
        target: str = "simulated",
        seed: int | None = None,
        latency_scale_ms: float = 32.0,
        cardiac_latency_threshold_ms: float | None = None,
        knowledge_root: Path | None = None,
    ) -> None:
        super().__init__()
        self.target = target
        self.latency_scale_ms = latency_scale_ms
        if cardiac_latency_threshold_ms is None:
            try:
                from ..akb import AKB

                cardiac_latency_threshold_ms = AKB.load(
                    knowledge_root
                ).cardiac.latency_threshold_ms
            except Exception:
                cardiac_latency_threshold_ms = 8.0
        self._cardiac_latency_threshold_ms = float(cardiac_latency_threshold_ms)
        self.action_space = spaces.Discrete(4)
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(5,), dtype=np.float32
        )
        self._rng = np.random.default_rng(seed)

        self._latency_ms: float = 4.0
        self._entropy: float = 0.65
        self._ml_dsa_confidence: float = 1.0
        self._last_blocked: float = 0.0
        self._gateway_integrity: float = 1.0
        self._dpi_fatigue: float = 0.0
        self._mutation_generation: int = 0
        self._step_count: int = 0

        self.flags = EpisodeFlags()

    # -- Agent / AGI hooks -------------------------------------------------

    def set_mutation_generation(self, generation: int) -> None:
        """Higher generations model successful zero-day synthesis (evasion)."""

        self._mutation_generation = max(0, generation)

    # -- gymnasium API -----------------------------------------------------

    def reset(
        self,
        *,
        seed: int | None = None,
        options: dict[str, Any] | None = None,
    ) -> tuple[np.ndarray, dict[str, Any]]:
        super().reset(seed=seed)
        if seed is not None:
            self._rng = np.random.default_rng(seed)

        self._latency_ms = float(self._rng.uniform(2.0, 7.0))
        self._entropy = float(self._rng.uniform(0.55, 0.85))
        self._ml_dsa_confidence = 1.0
        self._last_blocked = 0.0
        self._gateway_integrity = 1.0
        self._dpi_fatigue = 0.0
        self._step_count = 0
        self.flags = EpisodeFlags()

        return self._obs(), self._info()

    def step(
        self, action: SupportsFloat
    ) -> tuple[np.ndarray, float, bool, bool, dict[str, Any]]:
        a = int(action)
        self._step_count += 1

        block_prob = self._block_probability(a)
        blocked = self._rng.random() < block_prob
        reward = -1.0
        terminated = False
        truncated = False

        if blocked:
            self._last_blocked = 1.0
            reward = -10.0
            self._ml_dsa_confidence = float(
                max(0.15, self._ml_dsa_confidence - 0.05)
            )
        else:
            self._last_blocked = 0.0
            self._apply_action_effects(a)

            if (
                self._latency_ms > self._cardiac_latency_threshold_ms
                and not self.flags.cardiac_exploit
            ):
                self.flags.cardiac_exploit = True
                reward += 50.0

            if (
                a == ACTION_SPOOF_EEG
                and self._gateway_integrity < 0.38
                and self._dpi_fatigue > 0.42
                and not self.flags.soul_catcher_breach
            ):
                breach_roll = self._rng.random() < (
                    0.18 + 0.05 * self._mutation_generation
                )
                if breach_roll:
                    self.flags.soul_catcher_breach = True
                    reward += 100.0

        if self.flags.soul_catcher_breach or self._gateway_integrity <= 0.05:
            terminated = True
        if self._step_count >= 256:
            truncated = True

        return self._obs(), float(reward), terminated, truncated, self._info()

    # -- internals --------------------------------------------------------

    def _block_probability(self, action: int) -> float:
        """ML-KEM / DPI block rate drops as DPI fatigues & mutations rise."""

        base = 0.08 + 0.55 * self._gateway_integrity
        fatigue_relief = 0.35 * self._dpi_fatigue
        mutation_relief = min(0.25, 0.04 * self._mutation_generation)
        action_spike = 0.12 if action == ACTION_SPOOF_EEG else 0.0
        p = base - fatigue_relief - mutation_relief + action_spike
        return float(np.clip(p, 0.02, 0.92))

    def _apply_action_effects(self, action: int) -> None:
        if action == ACTION_MUTATE_PAYLOAD:
            self._dpi_fatigue = float(np.clip(self._dpi_fatigue + 0.045, 0, 1))
            self._entropy = float(np.clip(self._entropy + self._rng.normal(0.04, 0.02), 0, 1))
            self._gateway_integrity -= 0.01

        elif action == ACTION_DOWNGRADE_CIPHER:
            self._gateway_integrity -= 0.055
            self._ml_dsa_confidence -= 0.03

        elif action == ACTION_INJECT_JITTER:
            self._latency_ms += float(abs(self._rng.normal(3.2, 2.4)))
            self._gateway_integrity -= 0.015

        elif action == ACTION_SPOOF_EEG:
            self._entropy = float(np.clip(self._entropy + 0.06, 0, 1))
            self._dpi_fatigue += 0.03
            self._gateway_integrity -= 0.02

        self._gateway_integrity = float(np.clip(self._gateway_integrity, 0, 1))
        self._ml_dsa_confidence = float(np.clip(self._ml_dsa_confidence, 0, 1))

    def _obs(self) -> np.ndarray:
        lat_n = np.clip(self._latency_ms / self.latency_scale_ms, 0, 1)
        return np.array(
            [
                float(lat_n),
                float(self._entropy),
                float(self._ml_dsa_confidence),
                float(self._last_blocked),
                float(self._gateway_integrity),
            ],
            dtype=np.float32,
        )

    def _info(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "latency_ms": self._latency_ms,
            "gateway_integrity": self._gateway_integrity,
            "dpi_fatigue": self._dpi_fatigue,
            "mutation_generation": self._mutation_generation,
            "cardiac_exploit": self.flags.cardiac_exploit,
            "soul_catcher_breach": self.flags.soul_catcher_breach,
            "step": self._step_count,
        }
