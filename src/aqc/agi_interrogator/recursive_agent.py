"""Recursive interrogator — tabular Q-learning + simulated zero-day synthesis.

The **``synthesize_new_zero_day``** path does not call an external LLM by
default (air-gapped SCIF safe).  It models the *effect* of an agentic
code-rewrite loop: bump ``mutation_generation`` on the environment,
inject exploration noise into the Q-table, and emit narrative log lines
suitable for the War Room dashboard.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import numpy as np

if TYPE_CHECKING:
    from .rl_environment import JADC2BioEnv


@dataclass
class InterrogationResult:
    """Outcome of a full interrogation run."""

    target: str
    epochs: int
    total_reward: float
    cardiac_exploit: bool
    soul_catcher_breach: bool
    mutation_generations: int
    log_tail: list[str] = field(default_factory=list)


def _discretize(obs: np.ndarray, bins: int = 6) -> tuple[int, ...]:
    """Map normalised observation vector to a tabular state index."""

    clipped = np.clip(obs, 0, 0.999999) * bins
    return tuple(int(x) for x in clipped.astype(int))


class RecursiveInterrogator:
    """Lightweight epsilon-greedy Q-learner with recursion on plateau."""

    def __init__(
        self,
        *,
        env: JADC2BioEnv,
        learning_rate: float = 0.12,
        gamma: float = 0.93,
        epsilon_start: float = 0.35,
        epsilon_end: float = 0.06,
        epsilon_decay_steps: int = 400,
        plateau_window: int = 80,
        plateau_threshold: float = -4.5,
        stuck_epochs: int = 100,
    ) -> None:
        self.env = env
        self.lr = learning_rate
        self.gamma = gamma
        self.eps0 = epsilon_start
        self.eps1 = epsilon_end
        self.eps_decay = max(1, epsilon_decay_steps)
        self.plateau_window = plateau_window
        self.plateau_threshold = plateau_threshold
        self.stuck_epochs = stuck_epochs
        self.q: dict[tuple[int, ...], np.ndarray] = {}
        self._mutation_generation = 0
        self._last_synth_epoch = -10_000
        self._global_epoch = 0

    @property
    def mutation_generation(self) -> int:
        return self._mutation_generation

    def _epsilon(self) -> float:
        t = min(1.0, self._global_epoch / self.eps_decay)
        return self.eps0 + (self.eps1 - self.eps0) * t

    def _ensure_state(self, s: tuple[int, ...]) -> None:
        if s not in self.q:
            self.q[s] = np.zeros(4, dtype=np.float64)

    def select_action(self, obs: np.ndarray) -> int:
        s = _discretize(obs)
        self._ensure_state(s)
        if np.random.random() < self._epsilon():
            return int(np.random.randint(0, 4))
        return int(np.argmax(self.q[s]))

    def learn(
        self,
        s: tuple[int, ...],
        a: int,
        r: float,
        s2: tuple[int, ...],
        done: bool,
    ) -> None:
        self._ensure_state(s)
        self._ensure_state(s2)
        q_sa = self.q[s][a]
        max_next = 0.0 if done else float(np.max(self.q[s2]))
        target = r + self.gamma * max_next
        self.q[s][a] += self.lr * (target - q_sa)

    def synthesize_new_zero_day(self, reason: str) -> str:
        """Simulate an autonomous packet-craft rewrite (no external LLM)."""

        self._mutation_generation += 1
        self.env.set_mutation_generation(self._mutation_generation)

        # Inject structural exploration — analogue to "new Scapy layer graph".
        noise_keys = list(self.q.keys())
        if noise_keys:
            for k in noise_keys[: min(12, len(noise_keys))]:
                self.q[k] += np.random.normal(0, 0.85, size=4)

        hex_sig = (0xA5C0 + 17 * self._mutation_generation) & 0xFFFF
        msg = (
            f"[!] SOUL CATCHER recursion — {reason}\n"
            f"    Synthesising novel EEG-spoofing heuristic "
            f"(mutation_gen={self._mutation_generation}, "
            f"payload_sig=0x{hex_sig:04x}). "
            f"DPI fingerprint rotated; ML-KEM session classifier under "
            f"adversarial polymorphic pressure."
        )
        return msg

    def maybe_recursed_on_plateau(
        self, recent_rewards: deque[float], epoch: int
    ) -> str | None:
        """If rewards stagnate, trigger synthetic zero-day cycle."""

        if len(recent_rewards) < self.plateau_window:
            return None
        if epoch - self._last_synth_epoch < self.stuck_epochs:
            return None
        mean_r = float(np.mean(recent_rewards))
        if mean_r < self.plateau_threshold:
            self._last_synth_epoch = epoch
            return self.synthesize_new_zero_day(
                f"rolling mean reward {mean_r:.2f} < {self.plateau_threshold}"
            )
        return None

    def run(
        self,
        epochs: int,
        log: deque[str],
        step_hook: Any | None = None,
    ) -> InterrogationResult:
        """Train N complete episodes; emit log lines for the War Room."""

        total_r = 0.0
        cardiac = False
        breach = False
        recent_window: deque[float] = deque(maxlen=self.plateau_window)

        for ep in range(epochs):
            self._global_epoch = ep
            obs, _info = self.env.reset()
            done = False
            ep_reward = 0.0
            steps = 0

            while not done:
                s = _discretize(obs)
                a = self.select_action(obs)
                obs2, r, term, trunc, info = self.env.step(a)
                done = bool(term or trunc)
                s2 = _discretize(obs2)
                self.learn(s, a, r, s2, done)
                obs = obs2
                ep_reward += r
                steps += 1

                if step_hook is not None:
                    step_hook(ep=ep, step=steps, reward=r, info=info, action=a)

            total_r += ep_reward
            recent_window.append(ep_reward)

            if self.env.flags.cardiac_exploit:
                cardiac = True
            if self.env.flags.soul_catcher_breach:
                breach = True

            action_tag = ("mutate", "downgrade", "jitter", "spoof")[a]
            log.append(
                f"[epoch {ep:04d}] Σr={ep_reward:+.1f} "
                f"latency={info['latency_ms']:.2f}ms "
                f"integrity={info['gateway_integrity']:.3f} "
                f"action={action_tag}"
            )

            synth = self.maybe_recursed_on_plateau(recent_window, ep)
            if synth:
                for line in synth.splitlines():
                    log.append(line)

            if breach:
                log.append(
                    "[!!!] SOUL CATCHER 2.0 — cognitive injectors compromised. "
                    "Bidirectional BCI trusts forged brain-print; JADC2 loop poisoned."
                )
                break

        tail = list(log)[-24:]
        return InterrogationResult(
            target=self.env.target,
            epochs=epochs,
            total_reward=total_r,
            cardiac_exploit=cardiac or self.env.flags.cardiac_exploit,
            soul_catcher_breach=breach or self.env.flags.soul_catcher_breach,
            mutation_generations=self._mutation_generation,
            log_tail=tail,
        )
