import struct
import logging
from config.config import OFFSET_TASKS, POINTER_SIZE, PAGE_OFFSET

logger = logging.getLogger(__name__)

class TaskStructIterator:
    """
    Role 1 Core Engine Component.
    Iterates through the doubly linked list of tasks in the Linux memory mapping.
    Yields PHYSICAL addresses that Role 2 can safely seek() to in the raw file.
    """
    def __init__(self, mapped_memory, init_task_offset):
        self.mapped_memory = mapped_memory
        self.init_task_offset = init_task_offset
        self.visited = set()

    def virt_to_phys(self, virt_addr):
        """
        Converts a Linux kernel virtual address to a physical file offset.
        Handles both the Kernel Text Region and the Direct Mapping Region.
        """
        # 1. Kernel Text/Data Region (where init_task is often compiled)
        if virt_addr >= 0xffffffff80000000:
            return virt_addr - 0xffffffff80000000
            
        # 2. Direct Mapping Region (dynamically allocated task_structs)
        if virt_addr >= PAGE_OFFSET:
            return virt_addr - PAGE_OFFSET
            
        return virt_addr

    def walk_tasks(self):
        """
        Generator that traverses the tasks.next linked list.
        Yields the PHYSICAL address of each discovered task_struct.
        """
        # Convert the starting virtual address to physical
        current_task_addr = self.virt_to_phys(self.init_task_offset)
        
        while True:
            # Shield against circular looping DoS
            if current_task_addr in self.visited:
                logger.warning(f"Circular mapping detected at {hex(current_task_addr)}. Breaking.")
                break
                
            self.visited.add(current_task_addr)
            
            # Find the pointer to the next task's list_head
            next_ptr_addr = current_task_addr + OFFSET_TASKS
            
            # Memory mapping bound check
            if next_ptr_addr + POINTER_SIZE > self.mapped_memory.size():
                logger.error(f"Out of bounds pointer read at {hex(next_ptr_addr)}.")
                break

            # Yield the current task_struct PHYSICAL address for Role 2
            yield current_task_addr
                
            # Read 8 bytes at the tasks.next pointer location
            self.mapped_memory.seek(next_ptr_addr)
            pointer_bytes = self.mapped_memory.read(POINTER_SIZE)
            
            # Unpack the 64-bit unsigned long long (little-endian)
            next_list_head = struct.unpack("<Q", pointer_bytes)[0]
            
            # If the literal pointer is 0 or invalid, break
            if next_list_head == 0:
                break
                
            # next_list_head points to the OFFSET_TASKS field of the next task_struct.
            # Subtract the offset to get the base virtual address of the next task_struct.
            next_virt_addr = next_list_head - OFFSET_TASKS
            
            # Convert virtual address to physical file offset
            current_task_addr = self.virt_to_phys(next_virt_addr)
            
            # If we looped back to init_task, the full list has been traversed
            if current_task_addr == self.virt_to_phys(self.init_task_offset):
                break

