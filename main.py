import requests

# Replace with your VirusTotal API key
API_KEY = "f752bfb31251fbde980864c4219f6f182bc93f882857ecfa30a45d0c56c4fb01"
VT_URL = "https://www.virustotal.com/api/v3/domains/"

def scan_website(domain):
    headers = {"x-apikey": API_KEY}
    response = requests.get(VT_URL + domain, headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious_votes = data["data"]["attributes"].get("last_analysis_stats", {}).get("malicious", 0)
        print(f"{domain}: {malicious_votes} malicious detections")
    else:
        print(f"Failed to scan {domain}. Error: {response.status_code}")

if __name__ == "__main__":
    domain = input("Enter a website domain to scan: ")
    scan_website(domain)
