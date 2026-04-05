import os
from core.ingestion import MemoryIngestor
from core.parsers.task_struct import TaskStructIterator
from config.config import INIT_TASK_OFFSET

# Hey Role 5 (Integration Lead)! 
# Make sure you import the process and network extractors from Role 2 and 3 here.
# Also, import your clean 'prepare_data_for_gui' function from integration.py!

def main():
    print("Starting Memory Forensics Engine...")
    
    # We are now testing against the actual laboratory memory dump!
    # memory_dump_file = "memDumpFiles/MemoryDump_Lab3.raw"
    memory_dump_file = "C:/Users/DELL/Downloads/FS-01.mem"
    
    if not os.path.exists(memory_dump_file):
        print(f"Waiting for {memory_dump_file} to be added...")
        return

    # Role 1's job is complete: Safely opening the file.
    with MemoryIngestor(memory_dump_file) as mapped:
        print("Memory successfully inside the engine without crashing!")

        # --- ROLE 1 Phase 2: Identify Linux Version Banner ---
        from core.scanner import KernelScanner, SignatureNotFoundError
        scanner = KernelScanner(mapped)
        print("Scanning for Linux Kernel Profile...")
        try:
            kernel_banner = scanner.find_linux_banner()
            print(f"[ROLE 1 ENGINE] Successfully Identified Kernel Profile: {kernel_banner}")
        except SignatureNotFoundError:
            print("[ROLE 1 ENGINE] WARNING: Could not find Linux banner!")
            
        print("\nStarting memory physical layout extraction...")
        # We start looking through memory blocks using a physical offset mapping.
        # NOTE: 0xffffffff82600000 is a Virtual Address placeholder and will trigger an Out of Bounds error
        # until we translate it down to a physical offset based on the Kernel banner above!
        iterator = TaskStructIterator(mapped, INIT_TASK_OFFSET)
        
        raw_processes_for_gui = []
        raw_connections_for_gui = []

        # Role 1 gives us the physical locations of everything:
        for struct_address in iterator.walk_tasks():
            print(f"[ROLE 1 ENGINE] Discovered task_struct at memory block: {hex(struct_address)}")
            
            # ==========================================
            # Hey Integration Lead (Role 5)!
            # ==========================================
            # This is where you tie everything together.
            # 
            # 1. Call Role 2's process extractor using this `struct_address`.
            # 2. Add that process dictionary to `raw_processes_for_gui`.
            #
            # 3. Call Role 3's network extractor using this `struct_address`.
            # 4. Add those connection dictionaries to `raw_connections_for_gui`.
            #
            # Finally, outside this loop, pass both lists into your GUI 
            # converter: prepare_data_for_gui()
            
            pass

if __name__ == "__main__":
    main()
