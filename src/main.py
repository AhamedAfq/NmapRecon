from scanner import run_nmap_scan
from cve_lookup import fetch_ip_info, fetch_pocs_and_print
from report_generator import generate_report

def main():
    # target_ip = "scanme.nmap.org"  # 🔹 Hardcoded target IP
    target_ip = "39.96.119.235"  # 🔹 Hardcoded target IP

    print(f"🔍 Scanning Target: {target_ip}")

    # Step 1: Run NMap scan
    nmap_results = run_nmap_scan(target_ip)
    print(f"✅ NMap Scan Complete: {nmap_results}")

    # Step 2: Fetch Shodan data
    shodan_results = fetch_ip_info(target_ip)
    print(f"✅ Shodan Data Retrieved: {shodan_results}")

    # Step 3: Fetch CVEs & POCs
    if "vulnerabilities" in shodan_results:
        cve_poc_data = fetch_pocs_and_print(target_ip, shodan_results.get("hostnames", []),
                                            shodan_results["vulnerabilities"])
    else:
        cve_poc_data = {}

    # Step 4: Generate security report
    generate_report(target_ip, nmap_results, shodan_results, cve_poc_data)
    print(f"📄 Security Report Generated: scan_report.json")

if __name__ == "__main__":
    main()
