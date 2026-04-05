# Memory Forensics Tool (Core Engine v1.0)

A modular, pure Python forensics tool for analyzing Kali Linux memory dumps. This tool extracts running processes, network connections, and loaded libraries through direct data structure parsers, bypassing the need for heavy external frameworks like Volatility. 

## Project Architecture & Directory Structure

This project is built around collaborative team limits. Please pay very close attention to which file belongs to your assigned role!

```text
MemoryForensics_Tool/

■ CORE ENGINE (Role 1: Done ✅)
├── config/
│   └── config.py            -> (Role 1) Default constants, generic Linux offsets, and magic numbers.
├── core/
│   ├── ingestion.py         -> (Role 1) `MemoryIngestor` maps large memory files fast using `mmap`.
│   └── scanner.py           -> (Role 1) High speed string-scanner to locate the Linux version.
│
■ DATA EXTRACTORS 
├── core/parsers/
│   ├── task_struct.py       -> (Role 1: Done) C-Struct iterator built with `struct` module. Safely loops physical boundaries.
│   ├── processes.py         -> (Role 2) Empty stub file! You need to unpack PIDs and Names from the struct.
│   └── network.py           -> (Role 3) Completed
│
■ INTEGRATION & GUI (Role 4 & 5)
├── run_bridge.py            -> (Role 5) The root script! You must plug Role 2 & 3's dictionary outputs into this file.
├── integration.py           -> (Role 5) Bridging scripts that format strict dictionaries for GUI rendering.
├── search_filter.py         -> (Role 5) Sub-string searches for front-end visual tables.
└── test_backend_data.py     -> (Role 4/5) Used to validate the end-to-end backend before wrapping it in PyQt6/Tkinter.
```

## How the Engine Operates

The tool relies on a strictly layered pipeline:
1. **Ingestion (Role 1):** We do not load the whole dump into RAM. We use `mmap.mmap()` for safe partial reading.
2. **Scanning (Role 1):** We use Boyer-Moore `mmap.find` searches instead of slow regex to find the kernel profile.
3. **Iteration (Role 1):** We read linked-list structures by mathematically parsing 8-byte C Pointers in `task_struct.py`, returning the isolated memory location to other teams.
4. **Extraction (Roles 2 & 3):** Teammates take those memory locations, and extract string text by reading adjacent offset boundaries.
5. **Display (Roles 4 & 5):** The raw text is passed safely through `integration.py` into a PyQt or CustomTkinter GUI.

## For Contributors (Next Steps)
Please check `CONTRIBUTING.md` for role-by-role workflows. 
- **Roles 2 & 3:** Open your assigned python stubs inside `core/parsers/`. We left plain English instructions at the top guiding you precisely on where to begin coding your extractions!
- **Role 4 & 5:** Open `run_bridge.py`. There are clear `# TODO` notices pointing exactly where your Python dictionaries map back into the main view.
