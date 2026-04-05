import os
import struct
import pytest
from core.ingestion import MemoryIngestor
from core.parsers.task_struct import TaskStructIterator
from config.config import OFFSET_TASKS

DUMMY_FILE = "dummy_list.raw"

@pytest.fixture
def dummy_linked_list_file():
    # We will build a 5000-byte raw file.
    mem = bytearray(b'\x00' * 5000)
    
    # Let task 1 (init_task) be at offset 100
    INIT_TASK = 100
    # Let task 2 be at offset 2000
    TASK_2 = 2000
    
    # Write pointer inside init_task pointing to task2's list_head
    mem[INIT_TASK + OFFSET_TASKS : INIT_TASK + OFFSET_TASKS + 8] = struct.pack("<Q", TASK_2 + OFFSET_TASKS)
    
    # Write pointer inside task2 pointing to init_task's list_head (circular loop complete)
    mem[TASK_2 + OFFSET_TASKS : TASK_2 + OFFSET_TASKS + 8] = struct.pack("<Q", INIT_TASK + OFFSET_TASKS)
    
    with open(DUMMY_FILE, "wb") as f:
        f.write(mem)
        
    yield DUMMY_FILE
    
    if os.path.exists(DUMMY_FILE):
        os.remove(DUMMY_FILE)

def test_circular_task_loop(dummy_linked_list_file):
    with MemoryIngestor(dummy_linked_list_file) as mapped:
        # Start iterating at exactly the initialized anchor (100)
        iterator = TaskStructIterator(mapped, init_task_offset=100)
        
        # Generator to list natively calls it
        found_addresses = list(iterator.walk_tasks())
        
        # We expect exactly 2 addresses (100 and 2000) before breaking on the circular back-pointer
        assert len(found_addresses) == 2
        assert found_addresses[0] == 100
        assert found_addresses[1] == 2000
