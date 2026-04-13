import os

def find_dockerfile(path):
    dockerfile_path = os.path.join(path, "Dockerfile")

    if os.path.exists(dockerfile_path):
        return dockerfile_path
    
    return None
