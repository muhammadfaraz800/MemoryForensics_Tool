# Advanced search function — name, PID, PPID, time 

def filter_processes(process_list, search_term):
    """
    Process search in:
    - name
    - pid (as string)
    - ppid (as string)
    - time (creation time)
    """
    if not search_term:
        return process_list
    
    search_term = search_term.lower()
    result = []
    
    for process in process_list:
        # Checking every field
        if (search_term in process.get('name', '').lower() or
            search_term in str(process.get('pid', '')).lower() or
            search_term in str(process.get('ppid', '')).lower() or
            search_term in process.get('time', '').lower()):
            result.append(process)
    
    return result


# Network connections search 
def filter_connections(conn_list, search_term):
    if not search_term:
        return conn_list
    
    search_term = search_term.lower()
    result = []
    
    for conn in conn_list:
        if (search_term in str(conn.get('pid', '')).lower() or
            search_term in conn.get('local_ip', '').lower() or
            search_term in str(conn.get('local_port', '')).lower() or
            search_term in conn.get('remote_ip', '').lower() or
            search_term in str(conn.get('remote_port', '')).lower() or
            search_term in conn.get('protocol', '').lower()):
            result.append(conn)
    
    return result


# Test code
if __name__ == "__main__":
    from dummy_data import sample_processes, sample_connections
    
    print("=== PROCESS SEARCH TESTS ===")
    print("1. Search by name 'malware':", filter_processes(sample_processes, "malware"))
    print("2. Search by PID '1234':", filter_processes(sample_processes, "1234"))
    print("3. Search by PPID '1':", filter_processes(sample_processes, "1"))
    print("4. Search by time '10:10':", filter_processes(sample_processes, "10:10"))
    
    print("\n=== CONNECTION SEARCH TESTS ===")
    print("5. Search by IP '185.130':", filter_connections(sample_connections, "185.130"))
    print("6. Search by port '4444':", filter_connections(sample_connections, "4444"))
    print("7. Search by protocol 'UDP':", filter_connections(sample_connections, "udp"))
