import nmap
# Network Scanner by Jared Myers
# Scan_Network function
def scan_network(target_ip, scan_type='-sS'):
    nm = nmap.PortScanner()

    # Run the scan on the target IP with the specified scan type
    nm.scan(hosts=target_ip, arguments=scan_type)

    for host in nm.all_hosts():
        print(f"Host : {host} ({nm[host].hostname()})")
        print(f"State : {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"Protocol : {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"Port : {port}\tState : {nm[host][proto][port]['state']}")


if __name__ == "__main__":
    target_ip = input("Enter target IP range or single IP (e.g., '192.168.1.1' or '192.168.1.0/24'): ")
    scan_type = input("Enter scan type (e.g., '-sS' for SYN scan, '-sV' for version detection): ")
    scan_network(target_ip, scan_type)