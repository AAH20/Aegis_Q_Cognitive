"""Smoke tests for the Interrogation AGI stack (optional ``[agi]`` extra)."""

from __future__ import annotations

from collections import deque

import pytest

pytest.importorskip("gymnasium")
pytest.importorskip("numpy")

from aqc.agi_interrogator import JADC2BioEnv, RecursiveInterrogator
from aqc.agi_interrogator.rl_environment import (
    ACTION_INJECT_JITTER,
    ACTION_MUTATE_PAYLOAD,
)


def test_jadc2_bio_env_reset_step() -> None:
    env = JADC2BioEnv(target="test", seed=42)
    obs, info = env.reset()
    assert obs.shape == (5,)
    assert 0 <= obs[0] <= 1
    assert info["target"] == "test"

    obs2, reward, term, trunc, info2 = env.step(ACTION_MUTATE_PAYLOAD)
    assert obs2.shape == (5,)
    assert isinstance(reward, float)
    assert isinstance(term, bool)
    assert isinstance(trunc, bool)
    assert "gateway_integrity" in info2


def test_recursive_interrogator_short_run() -> None:
    env = JADC2BioEnv(target="unit", seed=7)
    agent = RecursiveInterrogator(env=env, epsilon_decay_steps=20, plateau_window=5)
    log: deque[str] = deque(maxlen=100)
    res = agent.run(5, log)
    assert res.target == "unit"
    assert res.epochs == 5
    assert isinstance(res.total_reward, float)


def test_jitter_can_raise_latency() -> None:
    env = JADC2BioEnv(target="lat", seed=1)
    env.reset()
    latency = 0.0
    for _ in range(40):
        _, _, _, _, info = env.step(ACTION_INJECT_JITTER)
        latency = float(info["latency_ms"])
    assert latency > 4.0
