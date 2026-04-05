import logging
from config.config import LINUX_BANNER_MAGIC, MAX_BANNER_LENGTH

logger = logging.getLogger(__name__)

class SignatureNotFoundError(Exception):
    """Raised when a required kernel signature cannot be found in the memory dump."""
    pass

class KernelScanner:
    """
    Scans the mmap memory object for specifically known kernel signatures and structures.
    Uses Boyer-Moore built-in find() for linear high-performance scanning.
    """
    def __init__(self, mapped_memory):
        self.mapped_memory = mapped_memory

    def find_linux_banner(self) -> str:
        """
        Scans for 'Linux version ' and extracts the full version banner string.
        """
        # Go to start of memory space
        self.mapped_memory.seek(0)
        
        # Find the signature
        banner_offset = self.mapped_memory.find(LINUX_BANNER_MAGIC)
        if banner_offset == -1:
            raise SignatureNotFoundError("Could not find Linux version banner in the memory dump.")
            
        logger.info(f"Linux version banner found at offset: {hex(banner_offset)}")
        
        # Extract everything from the banner magic onwards to a null terminator or newline
        self.mapped_memory.seek(banner_offset)
        banner_bytes = self.mapped_memory.read(MAX_BANNER_LENGTH)
        
        # Find the boundary of the string
        end_idx = banner_bytes.find(b'\x00')
        newline_idx = banner_bytes.find(b'\n')
        
        # Choose the earliest boundary if both exist
        boundaries = [i for i in (end_idx, newline_idx) if i != -1]
        
        if boundaries:
            cut_idx = min(boundaries)
            banner_bytes = banner_bytes[:cut_idx]
            
        return banner_bytes.decode('ascii', errors='replace')

    def find_init_task_offset(self):
        """
        Placeholder for Phase 3 to find PID 1 start.
        """
        return None
