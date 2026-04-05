# ROADMAP.md

> **Current Phase**: Not started
> **Milestone**: v1.0

## Must-Haves (from SPEC)
- [ ] Read large dumps securely.
- [ ] Dynamic struct parsing.
- [ ] Extract process details.

## Phases

### Phase 1: Foundation (I/O & Memory Ingestion)
**Status**: ✅ Complete
**Objective**: Establish file I/O safely using buffering or memory-mapped files (`mmap`) while adhering to memory limits. Setup standard logging.
**Requirements**: REQ-01

### Phase 2: Kernel Signature & Profile Identification
**Status**: ✅ Complete
**Objective**: Parse memory chunk by chunk to identify the Linux version banner and anchor pointers indicating where system tasks begin.
**Requirements**: REQ-02

### Phase 3: Core Engine Parsing (`task_struct`)
**Status**: ⬜ Not Started
**Objective**: Find `init_task` (PID 1) and correctly walk through the `task_struct` list to grab PIDs, names, PPIDs, and timestamps.
**Requirements**: REQ-03, REQ-04, REQ-05

### Phase 4: Integration Bridge
**Status**: ⬜ Not Started
**Objective**: Feed extracted data dynamically into the Role 5/GUI mockup formats using Python dictionaries. Validate through the existing `integration.py`.
**Requirements**: REQ-06
