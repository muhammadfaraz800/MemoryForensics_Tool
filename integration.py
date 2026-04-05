
# Bridge between backend and GUI 

from dummy_data import sample_processes, sample_connections
from search_filter import filter_processes, filter_connections

def prepare_data_for_gui(raw_processes, raw_connections):
    """
    Backend se aaya hua raw data (jo memory dump se nikla hai)
    GUI ke liye clean format mein convert karta hai
    
    Input: 
        raw_processes - list of process dictionaries
        raw_connections - list of connection dictionaries
    
    Output:
        {
            'processes': cleaned_processes,
            'connections': cleaned_connections,
            'stats': {'total_processes': x, 'total_connections': y}
        }
    """
    
    # Clean Processes (Handle null values)
    cleaned_processes = []
    for p in raw_processes:
        # SECURITY FIX: Enforce stringent type mapping and string bounds
        clean_p = {
            'pid': str(p.get('pid', 'N/A'))[:20],
            'name': str(p.get('name', 'Unknown'))[:255],
            'ppid': str(p.get('ppid', 'N/A'))[:20],
            'time': str(p.get('time', 'N/A'))[:50]
        }
        cleaned_processes.append(clean_p)
    
    # Clean Connections
    cleaned_connections = []
    for c in raw_connections:
        # SECURITY FIX: Enforce string type casting and guard maximum lengths
        clean_c = {
            'pid': str(c.get('pid', 'N/A'))[:20],
            'local_ip': str(c.get('local_ip', 'N/A'))[:50],
            'local_port': str(c.get('local_port', 'N/A'))[:10],
            'remote_ip': str(c.get('remote_ip', 'N/A'))[:50],
            'remote_port': str(c.get('remote_port', 'N/A'))[:10],
            'protocol': str(c.get('protocol', 'N/A'))[:10]
        }
        cleaned_connections.append(clean_c)
    
    # Create Statistics (To show in GUI)
    stats = {
        'total_processes': len(cleaned_processes),
        'total_connections': len(cleaned_connections),
        'suspicious_count': count_suspicious(cleaned_processes)
    }
    
    return {
        'processes': cleaned_processes,
        'connections': cleaned_connections,
        'stats': stats
    }


def count_suspicious(processes):
    """
    Suspicious processes count karo
    Suspicious = naam mein 'malware', 'virus', 'hidden', ya unknown source
    """
    suspicious_keywords = ['malware', 'virus', 'rootkit', 'hidden', 'unknown']
    count = 0
    for p in processes:
        name_lower = p.get('name', '').lower()
        for keyword in suspicious_keywords:
            if keyword in name_lower:
                count += 1
                break
    return count


def search_in_prepared_data(prepared_data, search_term):
    """
    GUI ke prepared data mein search karna
    """
    if not search_term:
        return prepared_data
    
    filtered_processes = filter_processes(prepared_data['processes'], search_term)
    filtered_connections = filter_connections(prepared_data['connections'], search_term)
    
    return {
        'processes': filtered_processes,
        'connections': filtered_connections,
        'stats': {
            'total_processes': len(filtered_processes),
            'total_connections': len(filtered_connections),
            'suspicious_count': count_suspicious(filtered_processes)
        }
    }


# TEST CODE 

if __name__ == "__main__":
    print("=== INTEGRATION TEST ===\n")
    
    # Step 1: Prepare Dummy data 
    prepared = prepare_data_for_gui(sample_processes, sample_connections)
    
    print("1. CLEANED PROCESSES:")
    for p in prepared['processes']:
        print(f"   PID: {p['pid']}, Name: {p['name']}, PPID: {p['ppid']}, Time: {p['time']}")
    
    print("\n2. CLEANED CONNECTIONS:")
    for c in prepared['connections']:
        print(f"   PID: {c['pid']}, {c['local_ip']}:{c['local_port']} -> {c['remote_ip']}:{c['remote_port']} ({c['protocol']})")
    
    print(f"\n3. STATISTICS:")
    print(f"   Total Processes: {prepared['stats']['total_processes']}")
    print(f"   Total Connections: {prepared['stats']['total_connections']}")
    print(f"   Suspicious Count: {prepared['stats']['suspicious_count']}")
    
    print("\n4. SEARCH TEST (searching for 'malware'):")
    search_result = search_in_prepared_data(prepared, "malware")
    print(f"   Found {search_result['stats']['total_processes']} matching processes")
    for p in search_result['processes']:
        print(f"   -> {p['name']} (PID: {p['pid']})")
