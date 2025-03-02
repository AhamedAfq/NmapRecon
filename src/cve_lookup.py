import requests

SHODAN_API_URL = "https://internetdb.shodan.io"


def fetch_ip_info(ip):
    """
    Fetches open ports, CPEs, and vulnerabilities for a given IP using Shodan's InternetDB API.
    """
    try:
        response = requests.get(f"{SHODAN_API_URL}/{ip}", timeout=10)
        if response.status_code == 200:
            data = response.json()

            # Extract relevant details
            ip_info = {
                "ip": data.get("ip"),
                "ports": data.get("ports", []),
                "cpes": data.get("cpes", []),
                "vulnerabilities": data.get("vulns", [])
            }
            return ip_info
        else:
            return {"error": f"API request failed: {response.status_code}"}

    except requests.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}


# Function to fetch and return POCs for a given CVE
def fetch_pocs_for_cve(cve_id):
    """
    Fetch Proof-of-Concept exploits from GitHub for a given CVE ID.
    """
    try:
        response = requests.get(f"https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve_id}")
        if response.status_code == 200:
            return response.json().get('pocs', [])
        else:
            print(f"[-] Failed to fetch POCs for {cve_id}")
    except requests.RequestException as e:
        print(f"[-] Error fetching POCs: {e}")
    return []


# Function to fetch POCs and print them
def fetch_pocs_and_print(ip, hostnames, cve_info):
    """
    Fetch POCs for discovered CVEs and display them.
    """
    found_cve_count = 0
    total_cve_count = len(cve_info)
    cve_data = {}

    for cve in cve_info:
        pocs = fetch_pocs_for_cve(cve)
        if pocs:
            found_cve_count += 1
            print(f"[+] Found POC for {cve}")
            print("  [+] Links:")
            for poc in pocs:
                print(f"    - {poc['html_url']}")

        if cve not in cve_data:
            cve_data[cve] = {'assets': [], 'pocs': []}
        cve_data[cve]['assets'].append(ip)
        cve_data[cve]['pocs'].extend([poc['html_url'] for poc in pocs])

    if found_cve_count > 0:
        print(f"[+] Found {found_cve_count}/{total_cve_count} CVEs with POCs for asset {ip}")

    return cve_data
