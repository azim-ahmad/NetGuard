
def analyze_host(host):
    findings = []

    risk_database = {
        "21": {
            "level": "Medium",
            "service": "FTP",
            "message": "FTP exposure detected. Check whether secure file transfer is configured."
        },
        "23": {
            "level": "High",
            "service": "Telnet",
            "message": "Telnet may transmit credentials without encryption. Prefer SSH."
        },
        "445": {
            "level": "High",
            "service": "SMB",
            "message": "SMB exposure detected. Review access controls and patch status."
        },
        "3389": {
            "level": "Medium",
            "service": "RDP",
            "message": "Remote Desktop exposure detected. Review access restrictions."
        },
        "22": {
            "level": "Info",
            "service": "SSH",
            "message": "SSH detected. Review authentication and access settings."
        },
        "5000": {
            "level": "Info",
            "service": "HTTP",
            "message": "Port 5000 is open. Check whether a development server is exposed."
        },
        "80": {
            "level": "Info",
            "service": "HTTP",
            "message": "HTTP detected. Review whether HTTPS is required."
        }
    }

    for port in host["ports"]:
        port_number = port["port"]

        if port_number in risk_database:
            finding = risk_database[port_number].copy()
            finding["port"] = port_number
            findings.append(finding)

    if not findings:
        findings.append({
            "level": "Info",
            "service": "General",
            "port": "-",
            "message": "No services matched the basic rule database."
        })

    host["findings"] = findings
    return host
