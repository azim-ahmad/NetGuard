
import subprocess
import xml.etree.ElementTree as ET
import ipaddress

def scan_network(target):
    try:
        network = ipaddress.ip_network(target, strict=False)

        # Keep scans limited to a small private lab network
        if not network.is_private or network.num_addresses > 256:
            return {"error": "Use a private lab network with at most 256 addresses."}

        command = [
            "nmap",
            "-sV",
            "-T3",
            "-oX", "-",
            str(network)
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            return {"error": result.stderr or "Nmap scan failed"}

        root = ET.fromstring(result.stdout)
        hosts = []

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            address = host.find("address")
            ip = address.get("addr") if address is not None else "Unknown"

            ports = []
            for port in host.findall(".//port"):
                state = port.find("state")
                service = port.find("service")

                if state is not None and state.get("state") == "open":
                    ports.append({
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "service": service.get("name", "unknown") if service is not None else "unknown",
                        "version": service.get("version", "") if service is not None else ""
                    })

            hosts.append({"ip": ip, "ports": ports})

        return {"hosts": hosts}

    except (ValueError, subprocess.TimeoutExpired) as error:
        return {"error": str(error)}



