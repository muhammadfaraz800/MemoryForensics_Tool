---
phase: 1
plan: 1
wave: 1
---

# Plan 1.1: Core Memory Ingestion Engine

## Objective
Establish the foundational file I/O safely using python's `mmap` module to analyze raw memory dumps without consuming extreme RAM allocations (adhering to the <40% constraint). Set up standard logging and basic project structure.

## Context
- .gsd/SPEC.md
- .gsd/ARCHITECTURE.md
- integration.py (Target dictionary model)

## Tasks

<task type="auto">
  <name>Setup Configuration & Project Structure</name>
  <files>config/config.py, core/__init__.py, config/__init__.py</files>
  <action>
    Create the central `config.py` declaring the constants for parsing.
    - Set `MEMORY_LIMIT_PCT = 0.40`.
    - Set default `LOG_LEVEL = "INFO"`.
    - Set chunk limits for when mmap fallback is needed.
  </action>
  <verify>python -c "import config.config; print(config.config.MEMORY_LIMIT_PCT)"</verify>
  <done>Configuration imports smoothly and variable is available.</done>
</task>

<task type="auto">
  <name>Implement Memory Ingestion logic via mmap</name>
  <files>core/ingestion.py</files>
  <action>
    Implement `MemoryIngestor` class that takes a file path.
    - If the file exists, it uses `mmap.mmap()` with `access=mmap.ACCESS_READ`.
    - Includes a context manager (`__enter__`, `__exit__`) to safely close resources.
    - Raise custom errors if the file doesn't exist or is empty.
  </action>
  <verify>python -c "from core.ingestion import MemoryIngestor; print(hasattr(MemoryIngestor, '__enter__'))"</verify>
  <done>MemoryIngestor handles I/O securely under context management.</done>
</task>

<task type="auto">
  <name>Write dummy integration test</name>
  <files>tests/test_ingestion.py</files>
  <action>
    Create a test file that generates a temporary 10MB dummy binary file.
    - Validate that `MemoryIngestor` successfully maps it without reading fully into RAM (no `read()` of the entire file blindly).
    - Ensure it cleans up the dummy file afterward.
  </action>
  <verify>python -m pytest tests/test_ingestion.py</verify>
  <done>Pytest logs successful execution of the mmap on dummy binary data.</done>
</task>

## Success Criteria
- [ ] Central config is ready.
- [ ] Safe `mmap` file ingestion works contextually.
- [ ] Passing pytest suit for I/O bounds.


NON TECHNICAL PART:
COMMENTS: MAKE SURE THAT ONLY THOSE FILES ARE COMMITED THAT ARE NEEDED FOR TEAM WORK AND/OR TECHNICAL/USER DOCUMENTATION. 
THE GITHUB REPO URL IS: https://github.com/rijafatimaHope/MemoryForensics_Tool/

THIS REPO IS NOT MINE

THE FOLDERS SHOULD BE ARRANGED IN SUCH A WAY THAT EVEN NON TECHNICAL PERSON SEE TH DIRECTOTY STRUCTURE HE KNOWS WHAT IS WHERE. KEEP 5 ROLES IN MIND. IF THE FOLDER ONLY CONTAIN 1 FILE DONT HESITATE IN CREATING THAT FOLDER