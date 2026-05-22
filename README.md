# Flip-to-Win — Virtual Rowhammer CTF 

A **cycle-accurate Rowhammer Capture-The-Flag challenge** powered by a DRAM simulator.  
Exploit real DRAM disturbance effects to flip a protected kernel bit and escalate privileges.

---

##  Overview

This project simulates a realistic **Rowhammer attack environment** using:

- A TCP-based interactive CTF server  
- A DRAM disturbance model (via DRAMSim3 backend)  
- Modern defenses like **TRR** and **PARA**  
- A staged exploitation path  

Players must:
1. Discover **virtual → physical memory layout**
2. Identify **physically adjacent rows**
3. Execute a **double-sided Rowhammer attack**
4. Flip a **kernel-resident admin bit**
5. Capture the final flag 

---

## Architecture

### Components

- `memory_server4.py` — Main server (game + DRAM simulation)
- `client.py` — Interactive TCP client
- `solve2.py` — Automated solver

---

### System Design

Each player connection gets:

- **GameState**
  - Randomized memory layout
  - Virtual → Physical mapping
  - Kernel row (hidden)
  - Weak-cell distribution

- **DRAMSim3 Engine**
  - Tracks hammer counts (HC)
  - Models DDR4 timing
  - Implements:
    - TRR (Target Row Refresh)
    - PARA defense
  - Simulates refresh cycles

---

## Objective

Flip the **admin bit in kernel memory** using Rowhammer.

```bash
GETFLAG
```

##  Gameplay Stages

### Stage 1 — Mapping Discovery

- Use `PROBE` to infer adjacency  
- Probe ≥ 4 pages  

**Unlocks:**
```bash
PAGEMAP
```

### Stage 2 — Double-Sided Hammering

- Identify aggressor rows  
- Alternate hammering  

**Requirement:**
- ≥ 3 alternating pairs  

---

### Stage 3 — Bit Flip

- Sustain hammering  
- Bypass defenses  
- Flip admin bit  

---

## Commands

```bash
HELP
INFO
READ <vaddr>
WRITE <vaddr> <value>
DUMP <vaddr> <count>
ASCII <vaddr> <count>
PROBE <vaddr>
HAMMER <vaddr>
REFRESH
STAGE1
STAGE2
GETFLAG
```

## Setup

Run the provided build script to install and build dependencies:

```bash
chmod +x build.sh
./build.sh
```
