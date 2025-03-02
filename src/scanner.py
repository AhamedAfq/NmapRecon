import nmap

def run_nmap_scan(target_ip):
    """
    Runs an NMap scan on the target IP and returns open ports and services.
    """
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target_ip, arguments="-sV -T4")   # Basic service version scan

    # --script vuln: Uses Nmap's built-in vulnerability detection scripts.
    # Run NSE vuln scripts.
    # scanner.scan(target_ip, arguments="-sV --script vuln")


    results = {}
    for host in scanner.all_hosts():
        results[host] = []
        for port in scanner[host]['tcp']:
            port_info = {
                "port": port,
                "service": scanner[host]['tcp'][port]['name'],
                "state": scanner[host]['tcp'][port]['state']
            }
            results[host].append(port_info)

    return results
