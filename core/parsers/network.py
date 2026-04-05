# ==========================================
# NETWORK FORENSICS ANALYST (Role 3) - Muhammad Abdullah
# ==========================================
import struct
import socket
from config.config import (
    POINTER_SIZE, OFFSET_FILES, OFFSET_FDT, OFFSET_FD_ARRAY,
    OFFSET_FILE_PRIVATE, OFFSET_SOCK_SK, OFFSET_INET_SPORT,
    OFFSET_INET_DPORT, OFFSET_INET_SADDR, OFFSET_INET_DADDR
)

def extract_network_connections(mapped_memory, struct_addr):
    """
    Extracts network connections for ONE process (given its task_struct address).
    Returns list of dicts ready for GUI + search.
    """
    connections = []
    try:
        # 1. task_struct -> files_struct
        mapped_memory.seek(struct_addr + OFFSET_FILES)
        files_struct_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]
        if files_struct_ptr == 0:
            return connections

        # 2. files_struct -> fdtable
        mapped_memory.seek(files_struct_ptr + OFFSET_FDT)
        fdt_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]

        # 3. fdtable -> fd_array
        mapped_memory.seek(fdt_ptr + OFFSET_FD_ARRAY)
        fd_array_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]

        # 4. Check first 256 file descriptors (sockets usually here)
        for i in range(256):
            mapped_memory.seek(fd_array_ptr + (i * POINTER_SIZE))
            file_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]
            if file_ptr == 0:
                continue

            # 5. file -> private_data (socket)
            mapped_memory.seek(file_ptr + OFFSET_FILE_PRIVATE)
            socket_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]
            if socket_ptr == 0:
                continue

            # 6. socket -> sock
            mapped_memory.seek(socket_ptr + OFFSET_SOCK_SK)
            sock_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]
            if sock_ptr == 0:
                continue

            # 7. Extract IP and Ports
            # Local IP
            mapped_memory.seek(sock_ptr + OFFSET_INET_SADDR)
            saddr_bytes = mapped_memory.read(4)
            local_ip = socket.inet_ntoa(saddr_bytes)

            # Remote IP
            mapped_memory.seek(sock_ptr + OFFSET_INET_DADDR)
            daddr_bytes = mapped_memory.read(4)
            remote_ip = socket.inet_ntoa(daddr_bytes)

            # Ports (network byte order → big-endian)
            mapped_memory.seek(sock_ptr + OFFSET_INET_SPORT)
            local_port = struct.unpack(">H", mapped_memory.read(2))[0]

            mapped_memory.seek(sock_ptr + OFFSET_INET_DPORT)
            remote_port = struct.unpack(">H", mapped_memory.read(2))[0]

            # Simple protocol guess (can be improved later)
            protocol = "TCP" if local_port < 65536 else "UDP"  # placeholder

            if local_ip != "0.0.0.0" or remote_ip != "0.0.0.0":
                connections.append({
                    "pid": 0,                    # TODO: Role 2 / integrator will fill this
                    "process_name": "unknown",   # TODO: extract from task_struct if needed
                    "protocol": protocol,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": "ESTABLISHED"       # TODO: parse sk_state for real state
                })

    except Exception:
        # Silently skip bad structures (common in memory dumps)
        pass

    return connections