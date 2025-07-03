import requests
import sys

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your VirusTotal API key
BASE_URL = "https://www.virustotal.com/api/v3/"

HEADERS = {
    "x-apikey": API_KEY
}

def scan_url(url):
    """Scan a URL using VirusTotal API."""
    endpoint = BASE_URL + "urls"
    # VirusTotal requires URL to be submitted as a SHA256 or base64 encoded, but for simplicity, we submit URL for analysis
    data = {"url": url}
    response = requests.post(endpoint, headers=HEADERS, data=data)
    if response.status_code == 200:
        analysis_url = response.json()['data']['id']
        return get_url_report(analysis_url)
    else:
        print(f"Error submitting URL for scanning: {response.status_code} {response.text}")
        return None

def get_url_report(analysis_id):
    """Get the URL scan report from VirusTotal."""
    endpoint = BASE_URL + f"analyses/{analysis_id}"
    response = requests.get(endpoint, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error getting URL report: {response.status_code} {response.text}")
        return None

def scan_ip(ip):
    """Scan an IP address using VirusTotal API."""
    endpoint = BASE_URL + f"ip_addresses/{ip}"
    response = requests.get(endpoint, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error getting IP report: {response.status_code} {response.text}")
        return None

def main():
    if API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        print("Please replace 'YOUR_VIRUSTOTAL_API_KEY' with your actual VirusTotal API key in the script.")
        sys.exit(1)

    if len(sys.argv) != 3:
        print("Usage: python scaaningtool.py <type> <value>")
        print("type: url or ip")
        print("value: the URL or IP address to scan")
        sys.exit(1)

    scan_type = sys.argv[1].lower()
    value = sys.argv[2]

    if scan_type == "url":
        print(f"Scanning URL: {value}")
        result = scan_url(value)
        if result:
            print("Scan result:")
            print(result)
    elif scan_type == "ip":
        print(f"Scanning IP: {value}")
        result = scan_ip(value)
        if result:
            print("Scan result:")
            print(result)
    else:
        print("Invalid type. Use 'url' or 'ip'.")

if __name__ == "__main__":
    main()
