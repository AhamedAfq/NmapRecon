import json

def generate_report(ip, nmap_results, shodan_results, cve_poc_data):
    """
    Generate a JSON security report including scan results, CVEs, and available POCs.
    """
    report = {
        "target_ip": ip,
        "nmap_scan_results": nmap_results,
        "shodan_results": shodan_results,
        "cve_pocs": cve_poc_data
    }

    with open("scan_report.json", "w") as report_file:
        json.dump(report, report_file, indent=4)

    print("📄 Report saved as scan_report.json")
