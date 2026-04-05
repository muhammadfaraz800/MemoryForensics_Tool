# Contributor Guide

Our development is strictly structured into 5 distinct domains. This centralized repository is the home for the finalized `MemoryIngestor` engine and Integration data structures. To avoid merge conflicts, ensure you are committing solely to your designated files.

## Project Roles & Responsibilities

### Role 1: Core Engine Developer (Team Lead)
- **Domain:** `/core/`, `/config/`, `/tests/`
- **Objective:** You handle raw file parsing and Linux memory profile resolution.
- **Workflow:** You manage system file I/O constraints, chunked `mmap` loading, and kernel signature locators. The entire foundation lives under your control.

### Role 2: Process & Library Analyst
- **Domain:** `/core/parsers/processes.py`, `/core/parsers/libraries.py` (To Be Built)
- **Objective:** You extract active programs and shared objects (`.so`) from the Linux dump.
- **Workflow:** Once Role 1 gives you the memory boundaries of an `init_task`, use Python's `struct` module to walk the doubly linked lists of `task_struct` and `mm_struct`, mapping PIDs to process names and creation times.

### Role 3: Network Forensics Analyst
- **Domain:** `/core/parsers/network.py` 
- **Objective:** Uncover all active internal network mappings and remote socket connections.
- **Workflow:** You parse the Network Namespace structures associated with Role 2's processes, decoding Local IP, Remote IP, and Port protocols accurately.

### Role 4: GUI Architect & Developer
- **Domain:** `/frontend/`, `/app.py`
- **Objective:** Produce the tool interface using PyQt6 or CustomTkinter.
- **Workflow:** You do not need to wait for the Core Engine! Work directly with the provided dictionaries within `dummy_data.py`. Build your tabular views and dashboards based strictly on that schema structure.

### Role 5: Integration, Search & QA Lead
- **Domain:** `integration.py`, `search_filter.py`, `test_backend_data.py`
- **Objective:** Build the bridging layer and filtering systems between the data structs and the UI tables.
- **Workflow:** You execute schema enforcement. If backend changes data paradigms, you update `integration.py`. If GUI needs complex logic resolving, you update `search_filter.py`.

## Git Workflows
- Keep branches decoupled. 
- Role 4 and Role 5 should freely test integrations by running `python test_backend_data.py`.
- Wait for Role 1 to deploy new signature extraction phases to the shared upstream `main` branch before writing deep parser logic.
