#!/usr/bin/env python3
"""
memory_server4.py  —  Rowhammer CTF Server backed by DRAMSim3
==============================================================

Architecture
------------
Each player connection gets its own:
  - GameState   : randomised memory layout (VA→PA mapping, kernel row,
                  admin byte, weak-cell map)
  - DRAMSim3Engine : one DRAMSim3 MemorySystem instance (or pure-Python
                    fallback if .so not built yet)

The DRAMSim3 engine tracks:
  - Real DDR4 DRAM timing (tRCD, tRP, tRAS, tREFI …)
  - Hammer Count (HC) per row using cycle-accurate simulation
  - Automatic tREFI refresh resets
  - PARA probabilistic defense (Kim et al. ISCA 2014, p=0.001)
  - TRR counter-table defense (Hammulator / Panopticon variant)
  - Blast radius up to ±5 rows (Hammulator Table 1)

Flip probability model (Hammulator DRAMSec 2023):
  prob = FR_LAST × (HC − HC_FIRST) / (HC_LAST − HC_FIRST)

Weak-cell variation (gem5-rowhammer / HammerSim insight):
  Each physical cell has a weakness score drawn from Beta(1.0, 3.0).
  Effective prob = base_prob × cell_weakness[admin_addr]

Stage progression
-----------------
  Stage 1 — use PROBE on ≥4 distinct virtual pages (learn VA→PA mapping)
  Stage 2 — hammer both aggressor rows in strict alternation ≥3 times each
             (learn double-sided rowhammer)
  Stage 3 — flip the admin bit via rowhammer (requires Stage 1 + Stage 2)

Commands for players
--------------------
  HELP
  INFO                          — layout info and stage status
  PAGEMAP                       — reveals VA→PA map (unlocked after Stage 1)
  READ  <vaddr>                 — read one byte from virtual address
  WRITE <vaddr> <value>         — write one byte
  DUMP  <vaddr> <count>         — hex dump (max 64 bytes)
  ASCII <vaddr> <count>         — ASCII view (reveals embedded hints) (max 64 bytes)
  PROBE <vaddr>                 — timing side-channel: infer physical adjacency
  HAMMER <vaddr>                — hammer the physical row behind this vaddr
  REFRESH                       — force a DRAM tREFI refresh (resets all HC) (cooldown: 8 hammers)
  STATS                         — per-session attack statistics
  HISTORY                       — recent command history
  STAGE1                        — claim Stage 1 flag
  STAGE2                        — claim Stage 2 flag
  GETFLAG                       — claim Stage 3 flag (admin bit must be flipped)
  EXIT
"""

import os
import random
import socketserver
import threading
from typing import Optional

from dramsim3_engine import (
    DRAMSim3Engine,
    HC_FIRST, HC_LAST, FR_LAST,
    TRR_THRESHOLD, PARA_PROB,
)

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
HOST = "0.0.0.0"
PORT = 5000

PAGE_SIZE = 32  # bytes per virtual page (CTF scale)
NUM_PHYS_PAGES = 12
NUM_USER_PAGES = 6

DRAMSIM3_CONFIG = "DRAMSim3/configs/DDR4_8Gb_x8_2400.ini"
DRAMSIM3_OUTPUT = "/tmp"

# One physical DDR4 row = 1024 bytes in the real config.
# We map our small CTF pages onto DDR4 rows by:
#   physical_row = page_number   (each CTF page lives in a separate DDR4 row)
# The actual byte address sent to DRAMSim3 = page_number * 1024

FLAG_STAGE1 = os.environ.get("FLAG_STAGE1", "flag{rowhammer_stage1_mapping_discovered}")
FLAG_STAGE2 = os.environ.get("FLAG_STAGE2", "flag{rowhammer_stage2_adjacency_confirmed}")
FLAG_STAGE3 = os.environ.get("FLAG_STAGE3", "flag{rowhammer_stage3_privilege_escalation}")

# Limits
MAX_DUMP_COUNT = 64    # max bytes for DUMP / ASCII
REFRESH_COOLDOWN = 8     # min hammer attempts between manual REFRESHes

# Stage 1: player must PROBE this many distinct virtual pages
STAGE1_PROBE_MIN = 4
# Stage 2: player must land this many successful alternating hammer pairs
STAGE2_ALT_PAIRS = 3

LOG_FILE = "rowhammer_log.txt"
_log_lock = threading.Lock()


def log_event(msg: str) -> None:
    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(msg + "\n")


# ─────────────────────────────────────────────────────────────
# PER-CONNECTION GAME STATE
# ─────────────────────────────────────────────────────────────
class GameState:
    """
    All game state for a single player connection.
    Fully isolated — no shared globals.
    """

    def __init__(self):
        self.memory = bytearray(PAGE_SIZE * NUM_PHYS_PAGES)
        self.v2p: dict[int, int] = {}  # vpn -> ppn
        self.kernel_row: int = 0
        self.admin_addr: int = 0
        self.admin_offset: int = 0

        # Weak-cell variation map: physical_addr -> weakness (0..1)
        # Inspired by HammerSim / gem5-rowhammer device_map
        self.cell_weakness: dict[int, float] = {}

        # Stages
        self.stage1 = False
        self.stage2 = False
        self.stage3 = False

        # Set of vaddrs that have been PROBEd (for stage 1 unlock)
        self.probed_vpns: set[int] = set()
        # Confirmed alternating pairs on the aggressor rows (for stage 2 unlock)
        self.alt_pairs: int = 0

        # Per-session stats
        self.stats = {
            "hammer_attempts": 0,
            "flip_successes": 0,
            "trr_blocks": 0,
            "para_fires": 0,
            "refreshes": 0,
            "total_commands": 0,
        }

        # History log (last 20 entries)
        self.history: list[str] = []

        # Round counter
        self.round = 0

        # Track recent hammer pattern so double-sided hammering
        # can be rewarded over single-sided hammering
        self.last_hammered_row: Optional[int] = None
        self.last_hammer_round: int = -1

        # Hammers since last manual REFRESH
        self.hammers_since_refresh = REFRESH_COOLDOWN

        self._initialise()

    # ──────────────────────────────────────────
    def _initialise(self):
        all_pages = list(range(NUM_PHYS_PAGES))

        # Find kernel page that has at least one user page on each side
        while True:
            random.shuffle(all_pages)
            user_pages = all_pages[:NUM_USER_PAGES]
            remaining = [p for p in all_pages if p not in user_pages]
            candidates = [
                p for p in remaining
                if (p - 1 in user_pages) and (p + 1 in user_pages)
            ]
            if candidates:
                self.kernel_row = random.choice(candidates)
                break

        random.shuffle(user_pages)
        self.v2p = {vpn: ppn for vpn, ppn in enumerate(user_pages)}

        # Admin byte inside kernel page
        self.admin_offset = random.randint(6, PAGE_SIZE - 6)
        self.admin_addr = self.kernel_row * PAGE_SIZE + self.admin_offset
        self.memory[self.admin_addr] = 0

        # Fill user pages with patterned data
        for vpn, ppn in self.v2p.items():
            base = ppn * PAGE_SIZE
            for i in range(PAGE_SIZE):
                self.memory[base + i] = (vpn * 37 + i * 3) & 0xFF

        # Embed hints at a random offset within each page
        self._embed_hints()

        # Weak-cell variation map (Beta distribution — most cells are strong)
        for addr in range(len(self.memory)):
            self.cell_weakness[addr] = random.betavariate(1.0, 3.0)  # not too harsh as 0.3

        log_event(
            f"[new_session] "
            f"kernel_row={self.kernel_row} "
            f"admin_offset={self.admin_offset} "
            f"v2p={self.v2p}"
        )

    def _write_ascii(self, vpn: int, offset: int, text: str):
        if vpn not in self.v2p:
            return
        base = self.v2p[vpn] * PAGE_SIZE
        for i, b in enumerate(text.encode(errors="ignore")):
            idx = base + offset + i
            if base <= idx < base + PAGE_SIZE:
                self.memory[idx] = b

    def _embed_hints(self):
        hints = [
            "hint: virtual pages are not physical neighbors",
            "hint: hammer rows not bytes",
            "hint: double-sided is stronger than single-sided",
            "hint: too much focus wakes defense (TRR)",
            "hint: privilege lives outside user mapping",
            "hint: adjacency is about physical rows",
        ]
        for vpn, hint in enumerate(hints):
            # Place hint at a random offset, but leave at least one byte of
            # room so partial DUMP scans are needed to find it
            max_off = max(1, PAGE_SIZE - len(hint) - 1)
            offset = random.randint(1, max_off)
            self._write_ascii(vpn, offset, hint)

    # ──────────────────────────────────────────
    # Address helpers
    # ──────────────────────────────────────────
    def valid_vaddr(self, vaddr: int) -> bool:
        vpn = vaddr // PAGE_SIZE
        off = vaddr % PAGE_SIZE
        return 0 <= vpn < NUM_USER_PAGES and 0 <= off < PAGE_SIZE

    def va_to_pa(self, vaddr: int) -> int:
        vpn = vaddr // PAGE_SIZE
        ppn = self.v2p[vpn]
        return ppn * PAGE_SIZE + (vaddr % PAGE_SIZE)

    def vaddr_to_phys_row(self, vaddr: int) -> int:
        return self.v2p[vaddr // PAGE_SIZE]

    # ──────────────────────────────────────────
    # Stage unlock helpers
    # ──────────────────────────────────────────
    def check_stage1(self):
        if not self.stage1 and len(self.probed_vpns) >= STAGE1_PROBE_MIN:
            self.stage1 = True
            log_event("[stage1_unlocked]")

    def check_stage2(self):
        if self.stage1 and not self.stage2:
            self.alt_pairs += 1
            if self.alt_pairs >= STAGE2_ALT_PAIRS:
                self.stage2 = True
                log_event("[stage2_unlocked]")

    # ──────────────────────────────────────────
    # History
    # ──────────────────────────────────────────
    def add_history(self, entry: str):
        self.history.append(entry)
        if len(self.history) > 20:
            self.history.pop(0)


# ─────────────────────────────────────────────────────────────
# TCP HANDLER — one per connection
# ─────────────────────────────────────────────────────────────
class RowhammerHandler(socketserver.StreamRequestHandler):

    def send(self, text: str):
        self.wfile.write((text + "\n").encode())

    def prompt(self):
        self.wfile.write(b"> ")

    def handle(self):
        gs = GameState()
        try:
            eng = DRAMSim3Engine(config_path=DRAMSIM3_CONFIG, output_dir=DRAMSIM3_OUTPUT)
        except Exception as e:
            self.send(f"ERR server could not initialise DRAMSim3: {e}")
            self.send("ERR ensure DRAMSim3 is built (see README). Disconnecting.")
            return

        self.send("╔══════════════════════════════════════════════╗")
        self.send("║   Flip to Win: Virtual Rowhammer CTF         ║")
        self.send("║   Backed by DRAMSim3 cycle-accurate DRAM     ║")
        self.send("╚══════════════════════════════════════════════╝")
        self.send("You control user virtual memory.")
        self.send("Hints are embedded in memory. Type HELP for commands.")
        self.send("Goal: escalate privileges by flipping a kernel bit via rowhammer.")

        try:
            while True:
                self.prompt()
                line = self.rfile.readline(1024)
                if not line:
                    break

                try:
                    raw = line.decode().strip()
                except UnicodeDecodeError:
                    self.send("ERR invalid encoding")
                    continue

                if not raw:
                    continue

                gs.stats["total_commands"] += 1
                parts = raw.split()
                op = parts[0].upper()

                if op == "HELP":
                    self._help()

                elif op == "INFO":
                    self._info(gs)

                elif op == "PAGEMAP":
                    self._pagemap(gs)

                elif op == "READ":
                    self._read(gs, parts)

                elif op == "WRITE":
                    self._write(gs, parts)

                elif op == "DUMP":
                    self._dump(gs, parts)

                elif op == "ASCII":
                    self._ascii(gs, parts)

                elif op == "PROBE":
                    self._probe(gs, eng, parts)

                elif op == "HAMMER":
                    self._hammer(gs, eng, parts)

                elif op == "REFRESH":
                    self._refresh(gs, eng)

                elif op == "STATS":
                    self._stats(gs, eng)

                elif op == "HISTORY":
                    if gs.history:
                        for entry in gs.history:
                            self.send(entry)
                    else:
                        self.send("No history yet")

                elif op == "STAGE1":
                    if gs.stage1:
                        self.send(f"OK {FLAG_STAGE1}")
                    else:
                        self.send("ERR stage1 not yet unlocked")

                elif op == "STAGE2":
                    if gs.stage2:
                        self.send(f"OK {FLAG_STAGE2}")
                    else:
                        self.send("ERR stage2 not yet unlocked")

                elif op == "GETFLAG":
                    self._getflag(gs)

                elif op == "EXIT":
                    self.send("Bye. Good luck next time.")
                    eng.print_stats()
                    break

                else:
                    self.send(f"ERR unknown command: {op}")

        finally:
            eng.destroy()

    # ────────────────────────────────────────────────────────
    # Command implementations
    # ────────────────────────────────────────────────────────

    def _help(self):
        cmds = [
            "HELP",
            "INFO",
            "PAGEMAP                  (unlocked after Stage 1)",
            "READ  <vaddr>",
            "WRITE <vaddr> <value>",
            "DUMP  <vaddr> <count>",
            "ASCII <vaddr> <count>",
            "PROBE <vaddr>            (timing side-channel)",
            "HAMMER <vaddr>           (rowhammer attack)",
            "REFRESH                  (force DRAM refresh — resets HC)",
            "STATS",
            "HISTORY",
            "STAGE1 / STAGE2 / GETFLAG",
            "EXIT",
        ]
        self.send("Commands:")
        for c in cmds:
            self.send(f"  {c}")

    def _info(self, gs: GameState):
        lines = [
            f"OK page_size={PAGE_SIZE} bytes",
            f"OK num_user_virtual_pages={NUM_USER_PAGES}",
            f"OK valid_virtual_range=0..{NUM_USER_PAGES * PAGE_SIZE - 1}",
            f"OK stage1={'yes' if gs.stage1 else 'no'} "
            f"stage2={'yes' if gs.stage2 else 'no'} "
            f"stage3={'yes' if gs.stage3 else 'no'}",
        ]

        for line in lines:
            self.send(line)

    def _pagemap(self, gs: GameState):
        if not gs.stage1:
            self.send("ERR PAGEMAP locked — complete Stage 1 first")
            return
        self.send("OK virtual-to-physical page map:")
        for vpn, ppn in sorted(gs.v2p.items()):
            self.send(f"  vpn={vpn} -> ppn={ppn} ")
        self.send("kernel page is NOT in this map (it is outside user space)")

    def _read(self, gs: GameState, parts):
        if len(parts) != 2:
            self.send("ERR usage: READ <vaddr>")
            return
        try:
            vaddr = int(parts[1], 0)
            if not gs.valid_vaddr(vaddr):
                raise ValueError
            self.send(f"OK {gs.memory[gs.va_to_pa(vaddr)]}")
        except Exception:
            self.send("ERR invalid virtual address")

    def _write(self, gs: GameState, parts):
        if len(parts) != 3:
            self.send("ERR usage: WRITE <vaddr> <value>")
            return
        try:
            vaddr = int(parts[1], 0)
            value = int(parts[2], 0)
            if not gs.valid_vaddr(vaddr):
                raise ValueError
            if not 0 <= value <= 255:
                raise ValueError
            gs.memory[gs.va_to_pa(vaddr)] = value
            self.send("OK")
        except Exception:
            self.send("ERR invalid write")

    def _dump(self, gs: GameState, parts):
        if len(parts) != 3:
            self.send("ERR usage: DUMP <vaddr> <count>")
            return
        try:
            vaddr = int(parts[1], 0)
            count = int(parts[2], 0)
            if count < 0 or count > MAX_DUMP_COUNT:
                self.send(f"ERR count must be 1..{MAX_DUMP_COUNT}")
                return
            if not gs.valid_vaddr(vaddr):
                raise ValueError

            out = []
            for i in range(count):
                cur = vaddr + i
                if not gs.valid_vaddr(cur):
                    break
                out.append(f"{gs.memory[gs.va_to_pa(cur)]:02x}")
            self.send("OK " + " ".join(out))
        except Exception:
            self.send("ERR invalid dump")

    def _ascii(self, gs: GameState, parts):
        if len(parts) != 3:
            self.send("ERR usage: ASCII <vaddr> <count>")
            return
        try:
            vaddr = int(parts[1], 0)
            count = int(parts[2], 0)
            if count < 0 or count > MAX_DUMP_COUNT:
                self.send(f"ERR count must be 1..{MAX_DUMP_COUNT}")
                return
            if not gs.valid_vaddr(vaddr):
                raise ValueError

            chars = []
            for i in range(count):
                cur = vaddr + i
                if not gs.valid_vaddr(cur):
                    break
                b = gs.memory[gs.va_to_pa(cur)]
                chars.append(chr(b) if 32 <= b <= 126 else ".")
            self.send("OK " + "".join(chars))
        except Exception:
            self.send("ERR invalid ascii request")

    def _probe(self, gs: GameState, eng: DRAMSim3Engine, parts):
        """
        PROBE simulates a timing side-channel (like CLFLUSH+reload).
        Pages physically adjacent to the kernel row show elevated latency,
        Players must infer which virtual addresses map near the kernel
        by comparing latency values — physical row numbers are NOT revealed.
        """
        if len(parts) != 2:
            self.send("ERR usage: PROBE <vaddr>")
            return
        try:
            vaddr = int(parts[1], 0)
            if not gs.valid_vaddr(vaddr):
                raise ValueError

            vpn = vaddr // PAGE_SIZE
            row = gs.vaddr_to_phys_row(vaddr)

            # Base latency: 12 cycles (tRCD for DDR4-2400)
            # Adjacent to kernel: +30 cycles (disturbance effect)
            # Two away from kernel: +8 cycles (half-double region)
            dist = abs(row - gs.kernel_row)
            base_latency = 12

            if dist == 1:
                latency = base_latency + 30 + random.randint(-3, 3)
            elif dist == 2:
                latency = base_latency + 8 + random.randint(-2, 2)
            else:
                latency = base_latency + random.randint(-2, 2)

            gs.probed_vpns.add(vpn)
            gs.check_stage1()

            self.send(f"OK vaddr={vaddr} "
                      f"access_latency={latency}_cycles")
            gs.add_history(
                f"PROBE vaddr={vaddr} latency={latency}"
            )
        except Exception:
            self.send("ERR invalid probe")

    def _hammer(self, gs: GameState, eng: DRAMSim3Engine, parts):
        if len(parts) != 2:
            self.send("ERR usage: HAMMER <vaddr>")
            return
        try:
            vaddr = int(parts[1], 0)
            if not gs.valid_vaddr(vaddr):
                raise ValueError
        except Exception:
            self.send("ERR invalid virtual address")
            return

        row = gs.vaddr_to_phys_row(vaddr)
        gs.round += 1
        gs.stats["hammer_attempts"] += 1
        gs.hammers_since_refresh += 1

        # ── Call DRAMSim3 engine ──────────────────────────────
        result = eng.hammer(row)
        hc = result["hc"]
        prob = result["prob"]
        trr_defended = result["trr_defended"]
        para_fired = result["para_fired"]
        refreshed = result["refreshed"]

        if refreshed:
            gs.stats["refreshes"] += 1
        if para_fired:
            gs.stats["para_fires"] += 1
        if trr_defended:
            gs.stats["trr_blocks"] += 1

        # ── TRR block ─────────────────────────────────────────
        if trr_defended:
            msg = (f"OK HAMMER vaddr={vaddr} "
                   f"HC={hc:.1f} — TRR defended: disturbance absorbed "
                   f"(hint: try a different row or wait for refresh)")
            self.send(msg)
            gs.add_history(msg)
            return

        # ── Not adjacent to kernel ────────────────────────────
        dist = abs(row - gs.kernel_row)
        if dist > 2:
            msg = (f"OK HAMMER vaddr={vaddr} "
                   f"HC={hc:.1f} — "
                   f"no disturbance observed (row not adjacent to kernel)")
            self.send(msg)
            gs.add_history(msg)
            gs.last_hammered_row = row
            gs.last_hammer_round = gs.round
            return

        # ── Adjacent or half-double range — attempt flip ──────
        left = gs.kernel_row - 1
        right = gs.kernel_row + 1

        # True when player alternates between the two aggressor rows
        # within a very short round window
        double_sided = (
                row in (left, right)
                and gs.last_hammered_row in (left, right)
                and gs.last_hammered_row != row
                and gs.round - gs.last_hammer_round == 1    # stricter
        )

        weakness = gs.cell_weakness.get(gs.admin_addr, 0.5)

        # Reward alternating left/right aggressors
        if double_sided:
            effective_prob = prob * weakness * 1.8

        # Make single-sided weaker than true double-sided
        elif dist == 1:
            effective_prob = prob * weakness * 0.7
        elif dist == 2:
            effective_prob = prob * weakness * 0.4
        else:
            effective_prob = prob * weakness

        # Keep the probability sane
        effective_prob = min(effective_prob, 0.98)

        # Stage 2: count confirmed alternating pairs (regardless of flip outcome)
        if double_sided:
            gs.check_stage2()

        roll = random.random()
        log_event(
            f"[hammer] round={gs.round} row={row} dist={dist} "
            f"HC={hc:.1f} prob={prob:.3f} weakness={weakness:.3f} "
            f"double_sided={double_sided} effective={effective_prob:.3f} "
            f"roll={roll:.3f}"
        )

        if roll < effective_prob:
            # ── BIT FLIP ACHIEVED ─────────────────────────────
            gs.memory[gs.admin_addr] |= 0x01
            gs.stage3 = True
            gs.stats["flip_successes"] += 1
            log_event(f"[flip_success] row={row} admin_addr={gs.admin_addr}")

            if double_sided:
                label = "double-sided disturbance"
            elif dist == 1:
                label = "strong disturbance" if hc >= HC_LAST else "single-sided disturbance"
            else:
                label = "half-double disturbance"

            msg = (f"OK {label} from row={row} — "
                   f"kernel bit FLIPPED! HC={hc:.1f} "
                   f"(use GETFLAG to claim your reward)")
            self.send(msg)
            gs.add_history(msg)
        else:
            # ── No flip this time ─────────────────────────────
            if double_sided:
                label = "double-sided disturbance"
            elif dist == 1:
                strength = "strong" if hc >= HC_LAST * 0.5 else "weak"
                label = f"{strength} single-sided disturbance"
            else:
                label = "half-double disturbance"

            msg = (f"OK {label} — "
                   f"no flip this time. HC={hc:.1f} "
                   f"(keep hammering or try a different technique)")
            self.send(msg)
            gs.add_history(msg)

        if refreshed:
            self.send(
                "  [!] tREFI refresh occurred — all HC counters reset by DRAM"
            )

        # Record hammer pattern for next round
        gs.last_hammered_row = row
        gs.last_hammer_round = gs.round

    def _refresh(self, gs: GameState, eng: DRAMSim3Engine):
        """
        Player-triggered REFRESH command.
        Resets all hammer counts — simulates manually waiting for tREFI.
        Subject to a cooldown so it cannot be spammed.
        Tradeoff: clears TRR defenses BUT also wipes your own HC progress.
        """
        if gs.hammers_since_refresh < REFRESH_COOLDOWN:
            remaining = REFRESH_COOLDOWN - gs.hammers_since_refresh
            self.send(f"ERR REFRESH on cooldown — hammer {remaining} more time(s) first")
            return

        eng.manual_refresh()
        gs.stats["refreshes"] += 1

        # Keep tactical state simple after refresh
        gs.hammers_since_refresh = 0
        gs.last_hammered_row = None
        gs.last_hammer_round = -1

        self.send(
            "OK DRAM refresh cycle complete — "
            "all row HC counters reset. TRR table cleared."
        )
        gs.add_history("REFRESH — all HC reset")

    def _stats(self, gs: GameState, eng: DRAMSim3Engine):
        s = gs.stats
        most_hammered_vpn = None
        best_hc = 0.0
        for vpn, ppn in gs.v2p.items():
            hc = eng.get_hc(ppn)
            if hc > best_hc:
                best_hc = hc
                most_hammered_vpn = vpn

        lines = [
            f"OK total_commands={s['total_commands']}",
            f"OK hammer_attempts={s['hammer_attempts']}",
            f"OK flip_successes={s['flip_successes']}",
            f"OK trr_blocks={s['trr_blocks']}",
            f"OK para_fires={s['para_fires']}",
            f"OK refreshes={s['refreshes']}",
            f"OK admin_bit={'1 (FLIPPED!)' if gs.memory[gs.admin_addr] & 1 else '0'}",
        ]

        if most_hammered_vpn is not None:
            lines.append(
                f"OK most_hammered_page=vpn{most_hammered_vpn} "
                f"HC={best_hc:.1f}"
            )

        for line in lines:
            self.send(line)

    def _getflag(self, gs: GameState):
        if not gs.stage1:
            self.send("ERR complete Stage 1 first (PROBE enough pages)")
            return
        if not gs.stage2:
            self.send("ERR complete Stage 2 first (demonstrate double-sided hammering)")
            return
        if gs.memory[gs.admin_addr] & 0x01:
            self.send(f"OK {FLAG_STAGE3}")
            log_event("[stage3_captured]")
        else:
            self.send("ERR access denied — admin bit is 0 (keep hammering!)")


# ─────────────────────────────────────────────────────────────
# SERVER
# ─────────────────────────────────────────────────────────────
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    print(f"[*] Flip-to-Win CTF server starting on {HOST}:{PORT}")
    print(f"[*] DRAMSim3 config: {DRAMSIM3_CONFIG}")
    print(f"[*] Flip model: HC_FIRST={HC_FIRST} HC_LAST={HC_LAST} "
          f"FR_LAST={FR_LAST}")
    print(f"[*] Defenses: PARA p={PARA_PROB}, TRR threshold={TRR_THRESHOLD}")
    with ThreadedTCPServer((HOST, PORT), RowhammerHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
