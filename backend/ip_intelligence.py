import socket
import requests

def get_ip_intelligence(domain):

    result = {
        "ip": "Unknown",
        "country": "Unknown",
        "isp": "Unknown",
        "asn": "Unknown"
    }

    try:
        # Resolve domain to IP
        ip = socket.gethostbyname(domain)
        result["ip"] = ip

        # Query IP intelligence API
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        result["country"] = data.get("country", "Unknown")
        result["isp"] = data.get("isp", "Unknown")
        result["asn"] = data.get("as", "Unknown")

    except:
        pass

    return result