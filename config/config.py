# config.py
# Constants and configurations for MemoryForensics Tool

# The maximum percentage of system RAM we are allowed to use when chunking
MEMORY_LIMIT_PCT = 0.40

# Logging verbosity
LOG_LEVEL = "INFO"

# Default chunk sizes for reading (in bytes) if we fall back from mmap
DEFAULT_CHUNK_SIZE = 10 * 1024 * 1024  # 10 MB chunks

# Kernel Signature Definitions
LINUX_BANNER_MAGIC = b"Linux version "
MAX_BANNER_LENGTH = 128

# Task Struct Engine Offsets (Linux 64-bit generic placeholder profile)
INIT_TASK_OFFSET = 0xffffffff82600000
OFFSET_TASKS = 0x398
OFFSET_PID = 0x4d8
OFFSET_COMM = 0x6e8
POINTER_SIZE = 8

# Virtual-to-Physical Address Translation
# In Linux x86_64, kernel virtual addresses starting with 0xffff88...
# are in the "direct mapping" region. To convert them to physical
# offsets inside the .raw file, we subtract this base value.
PAGE_OFFSET = 0xffff880000000000

