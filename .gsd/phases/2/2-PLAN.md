---
phase: 2
plan: 1
wave: 1
---

# Plan 2.1: Kernel Signature Banner Scanning

## Objective
Implement a brute-force memory scanner to parse through the ingested `mmap` object chunk by chunk (or directly via `mmap.find`) to identify the `Linux version` banner and anchor pointers without relying on external system maps.

## Context
- .gsd/ROADMAP.md
- config/config.py
- core/ingestion.py

## Tasks

<task type="auto">
  <name>Configure Scanner Signatures</name>
  <files>config/config.py</files>
  <action>
    Add the required magic bytes and scanning configuration variables to `config/config.py`.
    - Add `LINUX_BANNER_MAGIC = b"Linux version "`
    - Add `MAX_BANNER_LENGTH = 128` (To prevent reading massive strings off the edge)
  </action>
  <verify>python -c "import config.config; print(config.config.LINUX_BANNER_MAGIC)"</verify>
  <done>Variables are added to the centralized config and importable.</done>
</task>

<task type="auto">
  <name>Implement KernelScanner Core Module</name>
  <files>core/scanner.py</files>
  <action>
    Create a `KernelScanner` class that initializes with an `mmap` object.
    - Implement `find_linux_banner()` using `mapped_memory.find()`.
    - Once the signature is found, extract the string until a null byte (`\x00`) or newline (`\n`), bounded by `MAX_BANNER_LENGTH`.
    - Raise a custom `SignatureNotFoundError` if the banner is not present.
    - Implement a placeholder `find_init_task_offset()` returning `None` (to expand in Phase 3).
  </action>
  <verify>python -c "from core.scanner import KernelScanner; print(hasattr(KernelScanner, 'find_linux_banner'))"</verify>
  <done>Scanner object defines the required parsing methods.</done>
</task>

<task type="auto">
  <name>Test Banner Scanning</name>
  <files>tests/test_scanner.py</files>
  <action>
    Create a `pytest` test for `KernelScanner`:
    - Create a dummy memory file containing random bytes and embed `...Linux version 5.10.0-kali3-amd64...\x00` in the middle.
    - Inject this file via `MemoryIngestor` from Phase 1.
    - Assert `find_linux_banner()` successfully parses and returns `"Linux version 5.10.0-kali3-amd64..."`.
    - Test failure when the banner is completely missing.
  </action>
  <verify>python -m pytest tests/test_scanner.py</verify>
  <done>Pytest confirms that the `KernelScanner` parses linear structures accurately from mmap.</done>
</task>

## Success Criteria
- [ ] Central config holds the search patterns.
- [ ] Efficient search implemented without blowing up RAM.
- [ ] Test harness successfully verifies the offset extraction logic.
