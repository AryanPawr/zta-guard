from core.docker_parser import find_dockerfile

def run_scan(path=".", target_url=None):
    print ("[ZTA GUARD] Starting scan...")

    print(f"Project path: {path}")

    dockerfile = find_dockerfile(path)

    if dockerfile:
        print("Dockerfile found")
    else:
        print("No Dockerfile found")

    if target_url:
        print(f"\n Target URL: {target_url}")


    print("\n scan initialized successfully. \n")
    
    # Placeholder for actual scanning logic
    # This is where you would implement the logic to scan the specified path
    # and generate a report based on the findings.