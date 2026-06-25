"""Fixed-length cell framing + WTF-PAD-style adaptive padding scheduler.

The scheduler keeps the cell stream looking like a live conversation even
when idle, by emitting dummy (padding) cells on a randomized timer. Real
messages preempt the next scheduled padding cell.
"""
from __future__ import annotations

import os
import queue
import random
import threading
import time
from typing import Callable, Optional

from . import config


def pad_plaintext(payload: bytes, cell_type: int) -> bytes:
    """Frame a payload into a fixed-size plaintext cell.

    Layout: [1 byte type][2 byte big-endian length][payload][random pad].
    """
    max_payload = config.CELL_PLAINTEXT_SIZE - 3
    if len(payload) > max_payload:
        raise ValueError(
            f"payload {len(payload)} exceeds max {max_payload} per cell"
        )
    header = bytes([cell_type]) + len(payload).to_bytes(2, "big")
    pad_len = config.CELL_PLAINTEXT_SIZE - len(header) - len(payload)
    return header + payload + os.urandom(pad_len)


def unpad_plaintext(cell: bytes) -> tuple[int, bytes]:
    """Return (cell_type, payload) from a fixed-size plaintext cell."""
    if len(cell) != config.CELL_PLAINTEXT_SIZE:
        raise ValueError("bad cell size")
    cell_type = cell[0]
    length = int.from_bytes(cell[1:3], "big")
    return cell_type, cell[3:3 + length]


def _sample_delay_s() -> float:
    """Exponential delay clamped to the configured range, in seconds."""
    ms = random.expovariate(1.0 / config.PADDING_MEAN_DELAY_MS)
    ms = max(config.PADDING_MIN_DELAY_MS, min(config.PADDING_MAX_DELAY_MS, ms))
    return ms / 1000.0


class PaddingScheduler:
    """Background sender that interleaves real and dummy cells.

    send_cell(cell_type, payload) is supplied by the transport. The caller
    enqueues real payloads; the scheduler decides timing and fills idle
    gaps with padding cells so the on-wire cadence is uniform.
    """

    def __init__(self, send_cell: Callable[[int, bytes], None]):
        self._send_cell = send_cell
        self._q: "queue.Queue[bytes]" = queue.Queue()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def enqueue(self, payload: bytes) -> None:
        self._q.put(payload)

    def _run(self) -> None:
        while not self._stop.is_set():
            time.sleep(_sample_delay_s())
            try:
                payload = self._q.get_nowait()
                self._send_cell(config.CELL_TYPE_DATA, payload)
            except queue.Empty:
                # Idle: emit a dummy cell to mask silence.
                self._send_cell(config.CELL_TYPE_PADDING, b"")
