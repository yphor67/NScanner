import csv
import subprocess
import sys

def perform_scan(ip_list, scan_type):
    results = []

    for ip in ip_list:
        print(f"Scanning {ip} using {scan_type.upper()} scan with service version detection...")

        # Perform the selected Nmap scan with service version detection
        if scan_type.lower() == 'no ping (-pn)':
            scan_command = ['nmap', '-T4', '--disable-arp-ping', '-sV', ip]
        elif scan_type.lower() == 'syn':
            scan_command = ['nmap', '-T4', '-sS', '-sV', ip]
        elif scan_type.lower() in ['udp', 'comprehensive (-a)']:
            scan_command = ['nmap', '-T4', f'-s{scan_type.lower()}', '-sV', ip]
        else:
            print(f"Scantype {scan_type.lower()} not supported.")
            continue

        try:
            scan_output = subprocess.check_output(scan_command, text=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while scanning {ip}: {e.output}")
            continue

        # Prepare scan results
        if "Host is up" in scan_output:
            open_ports = [line.split() for line in scan_output.splitlines()
                          if "open" in line and "tcp" in line]

            for port_data in open_ports:
                scan_result = {}
                scan_result['IP'] = ip
                scan_result['Status'] = 'Up'
                scan_result['Port'] = port_data[0].split('/')[0]
                scan_result['Service Name'] = port_data[2]
                scan_result['Service Version'] = port_data[3]
                results.append(scan_result)
        else:
            scan_result = {}
            scan_result['IP'] = ip
            scan_result['Status'] = 'Down'
            scan_result['Port'] = 'N/A'
            scan_result['Service Name'] = 'N/A'
            scan_result['Service Version'] = 'N/A'
            results.append(scan_result)

    return results

def save_to_csv(results, output_file):
    with open(output_file, mode='w', newline='') as file:
        fieldnames = ['IP', 'Status', 'Port', 'Service Name', 'Service Version']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scanner.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, 'r') as ip_file:
        ips_to_scan = [line.strip() for line in ip_file]

    scan_types = ['SYN', 'UDP', 'Comprehensive (-A)', 'No Ping (-PN)']

    print("Available Scan Types:")
    for i, scan_type in enumerate(scan_types, start=1):
        print(f"{i}. {scan_type}")

    try:
        choice = int(input("Enter the number of the scan type to perform (1-4): "))
        if choice < 1 or choice > len(scan_types):
            print("Invalid choice. Please select a valid scan type.")
        else:
            selected_scan = scan_types[choice - 1]
            scan_results = perform_scan(ips_to_scan, selected_scan)
            save_to_csv(scan_results, output_file)

            print(f"Scan completed using {selected_scan.upper()} scan with service version detection. Results saved to '{output_file}'.")
    except ValueError:
        print("Invalid input. Please enter a valid number for the scan type.")
