# SPEC.md — Project Specification

> **Status**: `FINALIZED`

## Vision
A foundational, performant memory forensics analysis tool tailored for Linux systems. The tool securely parses `.raw` format memory dumps to extract critical operating system structures like running processes, libraries, and network connections, using standard Python libraries to maximize portability and educational value.

## Goals
1. Process large `.raw` memory dumps reliably without crashing, limiting host memory usage to 25-40%.
2. Dynamically identify the Linux profile and safely traverse kernel structures (like `task_struct`) via memory offsets.
3. Bridge the raw extracted data directly to the frontend GUI through cleanly structured JSON outputs.

## Non-Goals (Out of Scope)
- Building a full feature-parity competitor to Volatility.
- Handling Windows memory dumps (the focus is Linux, specifically Kali).
- Directly utilizing heavy external dependencies where Python standard libraries (e.g. `struct`) suffice.

## Users
Digital forensics students and analysts who want a lightweight, inspectable memory parser or researchers validating basic process and network behaviors on Linux.

## Constraints
- **Technical**: Must predominantly use Python standard libraries (e.g., `mmap`, `struct`, `os`). Must parse pointers and doubly-linked lists manually. Maximum resource footprint bounded at 25-40% of host RAM.
- **Timeline**: Academic course project timeline.
- **Input Format**: Raw physical memory dumps (`.raw`).

## Success Criteria
- [ ] Successfully identify the Linux banner/signature.
- [ ] Locate `init_task` (PID 1).
- [ ] Traverse `task_struct` and correctly export all running processes to JSON.
- [ ] Parse `mm_struct` to identify loaded `.so` shared libraries.
- [ ] Process memory large files efficiently without Out-of-Memory (OOM) errors.
