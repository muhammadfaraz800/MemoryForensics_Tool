# Script for testing real data coming from backend

import json
from integration import prepare_data_for_gui, search_in_prepared_data

def test_with_real_data(processes_file, connections_file):
    """
    Backend se aayi files ko test karo
    
    Processes file format (JSON):
    [
        {"pid": 1, "name": "init", "ppid": 0, "time": "10:00:01"},
        ...
    ]
    
    Connections file format (JSON):
    [
        {"pid": 1234, "local_ip": "192.168.1.5", "local_port": 4444, 
         "remote_ip": "185.130.5.253", "remote_port": 80, "protocol": "TCP"},
        ...
    ]
    """
    
    # Read Files
    print("=== READING BACKEND DATA ===")
    with open(processes_file, 'r') as f:
        raw_processes = json.load(f)
    with open(connections_file, 'r') as f:
        raw_connections = json.load(f)
    
    print(f"Loaded {len(raw_processes)} processes and {len(raw_connections)} connections")
    
    # Prepare data 
    print("\n=== PREPARING DATA FOR GUI ===")
    prepared = prepare_data_for_gui(raw_processes, raw_connections)
    
    print(f"Total Processes: {prepared['stats']['total_processes']}")
    print(f"Total Connections: {prepared['stats']['total_connections']}")
    print(f"Suspicious Count: {prepared['stats']['suspicious_count']}")
    
    # Show sample data 
    print("\n=== SAMPLE PROCESSES (first 5) ===")
    for p in prepared['processes'][:5]:
        print(f"  PID: {p['pid']}, Name: {p['name']}, PPID: {p['ppid']}")
    
    print("\n=== SAMPLE CONNECTIONS (first 5) ===")
    for c in prepared['connections'][:5]:
        print(f"  PID: {c['pid']}, {c['local_ip']}:{c['local_port']} -> {c['remote_ip']}:{c['remote_port']}")
    
    # Search test
    print("\n=== SEARCH TESTS ===")
    
    # Test 1: PID search
    if prepared['processes']:
        first_pid = prepared['processes'][0]['pid']
        result = search_in_prepared_data(prepared, str(first_pid))
        print(f"Search by PID '{first_pid}': Found {result['stats']['total_processes']} processes")
    
    # Test 2: Common process search (init, systemd, etc.)
    result = search_in_prepared_data(prepared, "init")
    print(f"Search by name 'init': Found {result['stats']['total_processes']} processes")
    
    # Test 3: IP search in connections
    if prepared['connections']:
        first_ip = prepared['connections'][0]['local_ip']
        if first_ip != 'N/A':
            result = search_in_prepared_data(prepared, first_ip)
            print(f"Search by IP '{first_ip}': Found {result['stats']['total_connections']} connections")
    
    print("\n=== TEST COMPLETE ===")
    return prepared


# For Manual input 
if __name__ == "__main__":
    print("Backend Data Test Script")
    print("========================")
    print("Instructions:")
    print("1. Backend team se processes.json aur connections.json files lo")
    print("2. In files ko is script wali folder mein rakho")
    print("3. Phir yeh command run karo:")
    print("   python test_backend_data.py")
    print("\n--- WAITING FOR BACKEND DATA ---")
    
    # Will be tested automatically if the file existed 
    import os
    if os.path.exists("processes.json") and os.path.exists("connections.json"):
        print("\nFiles found! Running tests...\n")
        test_with_real_data("processes.json", "connections.json")
    else:
        print("\nFiles not found. Jab backend data aayega, tab yeh script run karna.")