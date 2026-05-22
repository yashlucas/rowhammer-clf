"""
dramsim3_engine.py
==================
Python wrapper around libdramsim3_bridge.so via ctypes.

This module gives the CTF server a clean Python API:

    engine = DRAMSim3Engine("DRAMSim3/configs/DDR4_8Gb_x8_2400.ini")
    hc = engine.hammer_row(phys_addr)          # returns hammer count
    engine.destroy()

Row flip probability follows the Hammulator paper model:
    prob = FR_LAST * (HC - HC_FIRST) / (HC_LAST - HC_FIRST)

Real DDR4 values from Kim et al. ISCA 2020 / Hammulator DRAMSec 2023:
    HC_FIRST = 139000   (DDR3), 50000 (DDR4)
    We scale these down for CTF playability.
"""

import ctypes
import os
import random
import threading
from pathlib import Path

# ─────────────────────────────────────────────
# Hammulator flip model parameters
# Scaled down from real DDR4 values for CTF speed
# Real DDR4: HC_FIRST=50000, HC_LAST=200000, FR_LAST=0.001
# CTF scale: divide by 10000 so players feel progress
# ─────────────────────────────────────────────
HC_FIRST  = 5        # activations before any flip is possible
HC_LAST   = 20       # activations for maximum flip rate
FR_LAST   = 0.85     # max flip rate at HC_LAST (85% chance per attempt)

# PARA defense: probability of refreshing an adjacent row on each activation
# From Kim et al. ISCA 2014 — p=0.001 eliminates all flips
PARA_PROB = 0.001    # very small — players must work hard to trigger it

# TRR: if a row is hammered more than this many times, it gets defended
TRR_THRESHOLD = 12
TRR_COOLDOWN  = 9363  # ~1 tREFI period in cycles — defended until next refresh


class DRAMSim3Engine:
    """
    One instance per player connection.
    Wraps a single DRAMSim3 MemorySystem instance.
    If the .so cannot be loaded (DRAMSim3 not built yet),
    falls back to pure-Python simulation so the server still works.
    """

    # Class-level lock + lib reference (shared across all instances)
    _lib      = None
    _lib_lock = threading.Lock()
    _lib_path = os.path.join(os.path.dirname(__file__), "libdramsim3_bridge.so")

    @classmethod
    def _load_lib(cls):
        """Load the shared library once. Returns True on success."""
        with cls._lib_lock:
            if cls._lib is not None:
                return True
            if not Path(cls._lib_path).exists():
                return False
            try:
                lib = ctypes.CDLL(cls._lib_path)

                # ds3_create
                lib.ds3_create.restype  = ctypes.c_int
                lib.ds3_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

                # ds3_destroy
                lib.ds3_destroy.restype  = None
                lib.ds3_destroy.argtypes = [ctypes.c_int]

                # ds3_hammer_row
                lib.ds3_hammer_row.restype  = ctypes.c_double
                lib.ds3_hammer_row.argtypes = [ctypes.c_int, ctypes.c_uint64,
                                               ctypes.c_int]

                # ds3_get_row_hc
                lib.ds3_get_row_hc.restype  = ctypes.c_double
                lib.ds3_get_row_hc.argtypes = [ctypes.c_int, ctypes.c_uint64]

                # ds3_reset_counts
                lib.ds3_reset_counts.restype  = None
                lib.ds3_reset_counts.argtypes = [ctypes.c_int]

                # ds3_get_cycle
                lib.ds3_get_cycle.restype  = ctypes.c_uint64
                lib.ds3_get_cycle.argtypes = [ctypes.c_int]

                # ds3_print_stats
                lib.ds3_print_stats.restype  = None
                lib.ds3_print_stats.argtypes = [ctypes.c_int]

                # Callback types
                READ_CB_TYPE    = ctypes.CFUNCTYPE(None, ctypes.c_uint64)
                REFRESH_CB_TYPE = ctypes.CFUNCTYPE(None)

                lib.ds3_register_read_callback.restype  = None
                lib.ds3_register_read_callback.argtypes = [ctypes.c_int,
                                                           READ_CB_TYPE]
                lib.ds3_register_refresh_callback.restype  = None
                lib.ds3_register_refresh_callback.argtypes = [ctypes.c_int,
                                                               REFRESH_CB_TYPE]
                cls._lib = lib
                cls._READ_CB_TYPE    = READ_CB_TYPE
                cls._REFRESH_CB_TYPE = REFRESH_CB_TYPE
                return True

            except OSError:
                return False

    # ──────────────────────────────────────────
    def __init__(self,
                 config_path: str = "DRAMSim3/configs/DDR4_8Gb_x8_2400.ini",
                 output_dir: str  = "/tmp"):
        self._handle   = -1
        self._use_real = False
        self._lock     = threading.Lock()

        # TRR table: row_number -> cycle_flagged
        self._trr_table: dict[int, int] = {}

        # Pure-Python fallback hammer counts (used when .so not available)
        self._py_hc: dict[int, float] = {}
        self._py_cycle: int = 0
        self._py_next_refresh: int = HC_FIRST * 200  # synthetic

        # Track refresh events
        self._refresh_count = 0

        # Try to load the real library
        if self._load_lib():
            handle = self._lib.ds3_create(
                config_path.encode(),
                output_dir.encode()
            )
            if handle >= 0:
                self._handle   = handle
                self._use_real = True

                # Keep a reference so Python GC doesn't collect the callbacks
                self._refresh_cb = self._REFRESH_CB_TYPE(self._on_refresh)
            
                self._lib.ds3_register_refresh_callback(
                    self._handle, self._refresh_cb
                )

        mode = "DRAMSim3 (real)" if self._use_real else "pure-Python fallback"
        print(f"[DRAMEngine] Initialised with {mode}")

    # ──────────────────────────────────────────
    # Internal callbacks
    # ──────────────────────────────────────────
    def _on_refresh(self):
        """Called by C bridge on every tREFI boundary."""
        self._refresh_count += 1
        # TRR: entries older than 1 refresh period expire automatically
        # (hammer_counts are reset inside the C bridge already)
        expired = [r for r, cyc in self._trr_table.items()
                   if (self._get_cycle() - cyc) >= TRR_COOLDOWN]
        for r in expired:
            del self._trr_table[r]

    # ──────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────
    def _get_cycle(self) -> int:
        if self._use_real:
            return int(self._lib.ds3_get_cycle(self._handle))
        return self._py_cycle

    def _get_hc(self, row: int) -> float:
        if self._use_real:
            return float(self._lib.ds3_get_row_hc(self._handle,
                                                   ctypes.c_uint64(row)))
        return self._py_hc.get(row, 0.0)

    def _flip_probability(self, hc: float) -> float:
        """
        Hammulator linear model:
          prob = FR_LAST * (HC - HC_FIRST) / (HC_LAST - HC_FIRST)
        Clamped to [0, FR_LAST].
        """
        if hc < HC_FIRST:
            return 0.0
        prob = FR_LAST * (hc - HC_FIRST) / (HC_LAST - HC_FIRST)
        return min(prob, FR_LAST)

    def _is_trr_defended(self, row: int) -> bool:
        if row not in self._trr_table:
            return False
        return (self._get_cycle() - self._trr_table[row]) < TRR_COOLDOWN

    def _maybe_apply_trr(self, row: int, hc: float):
        """Flag row in TRR table if HC exceeds threshold."""
        if hc >= TRR_THRESHOLD and row not in self._trr_table:
            self._trr_table[row] = self._get_cycle()

    def _apply_para(self, row: int) -> bool:
        """
        PARA defense: on each activation, each adjacent row has PARA_PROB
        chance of being refreshed (HC reset).
        Returns True if a refresh was triggered on a neighbor.
        """
        triggered = False
        for neighbor in [row - 1, row + 1]:
            if random.random() < PARA_PROB:
                if self._use_real:
                    # We can't selectively reset one row in C bridge,
                    # so we just zero out the Python-side TRR table for it
                    self._trr_table.pop(neighbor, None)
                else:
                    self._py_hc.pop(neighbor, None)
                triggered = True
        return triggered

    def _py_hammer(self, row: int) -> float:
        """Pure-Python hammer count increment with blast radius."""
        blast = {1: 1.0, 2: 0.3, 3: 0.1, 4: 0.05, 5: 0.01}
        self._py_hc[row] = self._py_hc.get(row, 0.0) + 1.0
        for dist, weight in blast.items():
            if row >= dist:
                self._py_hc[row - dist] = self._py_hc.get(row - dist, 0.0) + weight
            self._py_hc[row + dist] = self._py_hc.get(row + dist, 0.0) + weight

        self._py_cycle += 60  # ~50 ns per activation at DDR4-2400
        if self._py_cycle >= self._py_next_refresh:
            self._py_next_refresh += HC_FIRST * 200
            self._py_hc.clear()
            self._refresh_count += 1

        return self._py_hc.get(row, 0.0)

    # ──────────────────────────────────────────
    # Public API used by the CTF server
    # ──────────────────────────────────────────
    def hammer(self, row: int) -> dict:
        """
        Simulate one HAMMER operation on a physical row.

        Returns a dict with:
          hc           : float  — current hammer count after this activation
          prob         : float  — current flip probability (0..FR_LAST)
          trr_defended : bool   — TRR is protecting this row right now
          para_fired   : bool   — PARA refreshed a neighbor this cycle
          refreshed    : bool   — a tREFI refresh happened during this call
        """
        with self._lock:
            refresh_before = self._refresh_count

            # Step 1: get hammer count from simulator
            if self._use_real:
                # row_addr = row * 1024 (row size for DDR4_8Gb_x8_2400)
                row_addr = row * 1024
                hc = float(self._lib.ds3_hammer_row(
                    self._handle,
                    ctypes.c_uint64(row_addr),
                    ctypes.c_int(1)
                ))
            else:
                hc = self._py_hammer(row)

            refreshed = self._refresh_count > refresh_before

            # Step 2: apply PARA defense
            para_fired = self._apply_para(row)

            # Step 3: check / apply TRR
            self._maybe_apply_trr(row, hc)
            trr_defended = self._is_trr_defended(row)

            # Step 4: compute flip probability
            prob = 0.0 if trr_defended else self._flip_probability(hc)

            return {
                "hc":           hc,
                "prob":         prob,
                "trr_defended": trr_defended,
                "para_fired":   para_fired,
                "refreshed":    refreshed,
                "cycle":        self._get_cycle(),
            }

    def get_hc(self, row: int) -> float:
        """Return current hammer count for a row without hammering."""
        with self._lock:
            return self._get_hc(row)

    def manual_refresh(self):
        """Force a DRAM refresh — resets all hammer counts."""
        with self._lock:
            if self._use_real:
                self._lib.ds3_reset_counts(self._handle)
            else:
                self._py_hc.clear()
                self._py_cycle += 9363
            self._refresh_count += 1
            self._trr_table.clear()

    def print_stats(self):
        """Print DRAMSim3 internal statistics."""
        if self._use_real:
            self._lib.ds3_print_stats(self._handle)

    def destroy(self):
        """Free the DRAMSim3 instance. Call when player disconnects."""
        with self._lock:
            if self._use_real and self._handle >= 0:
                self._lib.ds3_destroy(self._handle)
                self._handle   = -1
                self._use_real = False

    def __del__(self):
        self.destroy()
