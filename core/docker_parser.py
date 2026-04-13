# core/docker_parser.py

import os

def find_dockerfile(path):
    dockerfile_path = os.path.join(path, "Dockerfile")

    if os.path.exists(dockerfile_path):
        return dockerfile_path

    return None


def parse_dockerfile(path):
    dockerfile_path = find_dockerfile(path)

    if not dockerfile_path:
        return None

    with open(dockerfile_path, "r") as file:
        lines = file.readlines()

    data = {
        "base_image": None,
        "user": None,
        "exposed_ports": []
    }

    for line in lines:
        line = line.strip()

        if line.startswith("FROM"):
            data["base_image"] = line.split(" ")[1]

        elif line.startswith("USER"):
            data["user"] = line.split(" ")[1]

        elif line.startswith("EXPOSE"):
            port = line.split(" ")[1]
            data["exposed_ports"].append(port)

    return data