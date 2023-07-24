import nmap
import csv

def scan_ips(ip_list):
    nm = nmap.PortScanner()
    results = []

    for ip in ip_list:
        print(f"Scanning {ip}...")

        # Perform the Nmap scan with additional options (-Pn for no ping scan)
        nm.scan(hosts=ip, arguments='-T4 -A -v -Pn')

        # Prepare scan results
        scan_result = {}
        scan_result['IP'] = ip
        if ip in nm.all_hosts():
            scan_result['Status'] = nm[ip].state()
            for proto in nm[ip].all_protocols():
                ports = []
                for port in nm[ip][proto].keys():
                    ports.append(f"{port}/{nm[ip][proto][port]['state']}")
                scan_result[proto] = ', '.join(ports)
        else:
            scan_result['Status'] = 'Not responding'

        results.append(scan_result)

    return results

def save_to_csv(results):
    csv_file = 'scan_results.csv'
    with open(csv_file, mode='w', newline='') as file:
        fieldnames = ['IP', 'Status', 'tcp', 'udp']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

if __name__ == "__main__":
    with open('ip.txt', 'r') as ip_file:
        ips_to_scan = [line.strip() for line in ip_file]

    scan_results = scan_ips(ips_to_scan)
    save_to_csv(scan_results)

    print("Scan completed. Results saved to 'scan_results.csv'.")

