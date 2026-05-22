# Flip to Win: A Virtual Rowhammer CTF Challenge

## Overview

This project is a Rowhammer-inspired CTF challenge built using:

* **DRAMSim3** for realistic DRAM timing
* A **custom Python Rowhammer model** (bit flips, TRR, PARA)
* A TCP server, client, and automated solver

---

## Requirements

* Docker Desktop

---

## Run on a New System

### 1. Open terminal in project folder

```powershell
cd "path\to\rowhammer-ctf"
```

---

### 2. Build Docker image

```powershell
docker build -t rowhammer-ctf .
```

---

### 3. Run container

```powershell
docker run -it --name rowhammer-ctf-container -v "${PWD}:/project" rowhammer-ctf bash
```

---

### 4. Build project inside container

```bash
cd /project
chmod +x build.sh
./build.sh
```

---

### 5. Set library path

```bash
export LD_LIBRARY_PATH=/project:$LD_LIBRARY_PATH
```

---

### 6. Start the server

```bash
python3 memory_server2.py
```

You should see:

```
[*] Flip-to-Win CTF server starting...
```

---

## Play the Challenge

Open a new terminal:

```powershell
docker exec -it rowhammer-ctf-container bash
```

Then:

```bash
cd /project
export LD_LIBRARY_PATH=/project:$LD_LIBRARY_PATH
python3 client.py
```

---

## Run Solver (Recommended)

```bash
docker exec -it rowhammer-ctf-container bash
cd /project
export LD_LIBRARY_PATH=/project:$LD_LIBRARY_PATH
python3 solve2.py
```

---

## Common Error

### Error:

```
Unable to find image 'rowhammer-ctf:latest' locally
```

### Fix:

```powershell
docker build -t rowhammer-ctf .
```

---

## Notes

* DRAMSim3 is automatically downloaded during build
* Do not remove `build.sh`
* Always set `LD_LIBRARY_PATH` before running

---

