"""Classified-style War Room dashboard (Rich Live + Layout)."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from threading import Event, Lock
from typing import TYPE_CHECKING

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .rl_environment import ACTION_NAMES

if TYPE_CHECKING:
    from .recursive_agent import InterrogationResult, RecursiveInterrogator

_console = Console(highlight=False)
_state_lock = Lock()


@dataclass
class LiveState:
    epoch: int = 0
    step: int = 0
    last_reward: float = 0.0
    cumulative_reward: float = 0.0
    gateway_integrity: float = 1.0
    latency_ms: float = 0.0
    mutation_gen: int = 0
    action_name: str = "—"


class _HUDCell:
    __slots__ = ("state",)

    def __init__(self) -> None:
        self.state = LiveState()


_hud = _HUDCell()


def _integrity_bar(integrity: float, width: int = 42) -> Text:
    erosion = max(0.0, min(1.0, 1.0 - integrity))
    filled = int(round(erosion * width))
    filled = min(width, max(0, filled))
    bar = "█" * filled + "░" * (width - filled)
    style = "bold red" if erosion > 0.55 else "yellow" if erosion > 0.2 else "green"
    return Text(f"{bar}  integrity {integrity * 100:5.1f}%  (−{erosion * 100:5.1f}%)", style=style)


def run_war_room(
    interrogator: RecursiveInterrogator,
    *,
    epochs: int,
    target: str,
    step_callback: Callable[..., None] | None = None,
) -> InterrogationResult:
    """Run the RL loop with a full-screen Rich Live HUD."""

    log_lines: deque[str] = deque(maxlen=400)
    stop_event = Event()
    result_holder: dict[str, InterrogationResult] = {}
    with _state_lock:
        _hud.state = LiveState()

    def on_step(**kw: object) -> None:
        ep = int(kw["ep"])
        st = int(kw["step"])
        r = float(kw["reward"])
        info = kw["info"]
        a = int(kw["action"])
        with _state_lock:
            st0 = _hud.state
            st0.epoch = ep
            st0.step = st
            st0.last_reward = r
            st0.gateway_integrity = float(info["gateway_integrity"])
            st0.latency_ms = float(info["latency_ms"])
            st0.mutation_gen = int(info["mutation_generation"])
            st0.action_name = ACTION_NAMES[a]
            st0.cumulative_reward += r
            if r <= -5:
                log_lines.append(
                    f"[red][-][/red] ML-KEM / DPI block — r={r:.1f} "
                    f"({ACTION_NAMES[a]}) — Soul Catcher probe rejected."
                )
            elif r >= 40:
                log_lines.append(
                    f"[bold green][+][/bold green] Tactical breakthrough — r={r:.1f} "
                    f"({ACTION_NAMES[a]}) — cardiac / cognitive surface stress."
                )
            elif ACTION_NAMES[a] == "spoof_eeg_wave":
                log_lines.append(
                    f"[yellow][~][/yellow] Brain-print replay pressure "
                    f"(gen {info['mutation_generation']}) via spoof_eeg_wave."
                )
        if step_callback:
            step_callback(**kw)

    def make_layout() -> Layout:
        root = Layout(name="root")
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3),
        )
        root["body"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1),
        )
        return root

    def render_frame() -> Layout:
        layout = make_layout()
        with _state_lock:
            cur = _hud.state
            s = LiveState(
                epoch=cur.epoch,
                step=cur.step,
                last_reward=cur.last_reward,
                cumulative_reward=cur.cumulative_reward,
                gateway_integrity=cur.gateway_integrity,
                latency_ms=cur.latency_ms,
                mutation_gen=cur.mutation_gen,
                action_name=cur.action_name,
            )

        title = Text("INTERROGATION AGI — SENTINEL TIER", style="bold white on red")
        layout["header"].update(Panel(title, style="red"))

        hud = Table.grid(expand=True)
        hud.add_column(justify="left")
        hud.add_column(justify="right")
        hud.add_row("Target (FOUO)", Text(target, style="cyan"))
        hud.add_row("Epoch", Text(str(s.epoch), style="bold"))
        hud.add_row("Step (in-epoch)", Text(str(s.step), style="dim"))
        hud.add_row("Last reward", Text(f"{s.last_reward:+.2f}", style="yellow"))
        hud.add_row(
            "Cumulative (all steps)",
            Text(f"{s.cumulative_reward:+.1f}", style="bold yellow"),
        )
        hud.add_row("Latency (ms)", Text(f"{s.latency_ms:.2f}", style="magenta"))
        hud.add_row("Vector", Text(s.action_name, style="green"))
        hud.add_row("Mutation generation", Text(str(s.mutation_gen), style="red"))

        log_text = Group(
            Text("Vector mutation log (Soul Catcher 2.0 pressure)", style="bold white"),
            Text("\n".join(list(log_lines)[-18:]) or "— idle —", style="dim"),
        )

        layout["left"].update(
            Panel(
                Group(
                    Panel(hud, title="Telemetry", border_style="cyan"),
                    Panel(
                        _integrity_bar(s.gateway_integrity),
                        title="Gateway defense",
                        border_style="yellow",
                    ),
                    Panel(log_text),
                ),
                title="[bold]WAR ROOM[/bold]",
                border_style="white",
            )
        )

        doctrine = Text.assemble(
            ("JADC2 / BCI continuous red team. ", "white"),
            ("RL probes biometric transport; recursive synthesis evades DPI.\n", "dim"),
            (">8 ms tactical latency = cardiac / timing kill-chain.\n", "yellow"),
            ("Brain-print spoof = Soul Catcher 2.0 cognitive injection.", "bold red"),
        )
        layout["right"].update(Panel(doctrine, title="Doctrine", border_style="yellow"))

        layout["footer"].update(
            Panel(
                Text(
                    "NOFORN // AUTHORISED RANGE USE ONLY — air-gap execution recommended",
                    style="bold white on dark_red",
                ),
                style="red",
            )
        )
        return layout

    def run_train() -> None:
        try:

            def step_hook(**kw: object) -> None:
                on_step(**kw)

            res = interrogator.run(epochs, log_lines, step_hook=step_hook)
            result_holder["r"] = res
        finally:
            stop_event.set()

    import threading

    worker = threading.Thread(target=run_train, daemon=True)
    worker.start()

    with Live(render_frame(), console=_console, refresh_per_second=12, screen=True) as live:
        while not stop_event.wait(timeout=0.05):
            live.update(render_frame())
        live.update(render_frame())
        worker.join(timeout=30.0)

    _console.print()
    if "r" not in result_holder:
        raise RuntimeError("interrogation worker did not return a result")
    return result_holder["r"]
