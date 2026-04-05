import mmap
import os
import logging
from config.config import LOG_LEVEL

logging.basicConfig(level=getattr(logging, LOG_LEVEL))
logger = logging.getLogger(__name__)

class MemoryIngestor:
    """
    Safely maps large raw memory dump files into memory using mmap, 
    avoiding out-of-memory errors. Implements context manager for safe cleanup.
    """
    def __init__(self, file_path):
        # SECURITY FIX: Resolve absolute path to thwart Relative Directory Traversal (e.g. ../../etc/shadow)
        self.file_path = os.path.abspath(file_path)
        
        # SECURITY FIX: Enforce whitelisted extensions to prevent arbitrary binary loading
        allowed_exts = ('.raw', '.dd', '.vmem', '.img', '.mem')
        if not self.file_path.endswith(allowed_exts):
            raise ValueError(f"Invalid memory dump extension. Must be one of: {allowed_exts}")

        self.file_obj = None
        self.mapped_memory = None

        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Memory dump file not found: {self.file_path}")
            
        self.file_size = os.path.getsize(self.file_path)
        if self.file_size == 0:
            raise ValueError(f"Memory dump file is empty: {self.file_path}")

    def __enter__(self):
        logger.info(f"Opening memory dump: {self.file_path} ({self.file_size / (1024*1024):.2f} MB)")
        try:
            self.file_obj = open(self.file_path, "rb")
            # Create a read-only memory map of the file
            self.mapped_memory = mmap.mmap(
                self.file_obj.fileno(), 
                length=0, 
                access=mmap.ACCESS_READ
            )
            return self.mapped_memory
        except Exception as e:
            logger.error(f"Failed to map memory dump: {e}")
            self.__exit__(None, None, None)
            raise e

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.mapped_memory:
            self.mapped_memory.close()
            logger.info("Closed memory map.")
        if self.file_obj:
            self.file_obj.close()
            logger.info(f"Closed file object: {self.file_path}")
