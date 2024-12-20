import re
import os
import subprocess
import argparse


universal_subdomains = []
bruted_subdomains = []


def create_folder(path):
    """Creates folder if it doesn't exist."""
    if not os.path.exists(path):
        os.makedirs(path)

def run_dig_query(query_type, domain, dns_server):
    """Runs a dig query and returns the result."""
    try:
        command = ["dig", query_type, domain, "@{}".format(dns_server)]
        result = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Error executing dig query: {e.output}")
        return None

def write_output_to_file(file_path, data):
    """Writes data to a specified file."""
    with open(file_path, "w") as f:
        f.write(data)

def extract_subdomains(domain, dig_output):
    l = []
    # Regular expression to find subdomains in NS and SOA records
    escaped_domain = re.escape(domain)
    pattern = rf'\b\S+{escaped_domain}\b'
    regex = re.compile(pattern)

    # Find all matching subdomains (both NS and SOA)
    for line in dig_output.split():
        l.extend(regex.findall(line))

    return l

def enumerate_dns_records(domain, dns_server, output_path):
    """Enumerates DNS records using dig commands."""
    records = []

    # Create domain folder if it doesn't exist
    domain_folder = os.path.join(output_path, domain)
    create_folder(domain_folder)

    # Run NS Query
    ns_query = run_dig_query("ns", domain, dns_server)
    if ns_query:
        write_output_to_file(os.path.join(domain_folder, "dns-query.txt"), ns_query)
        records.append(ns_query)
        subdomains = extract_subdomains(domain, ns_query)

        if subdomains:
            for subdomain in subdomains:
                if subdomain not in universal_subdomains:
                    universal_subdomains.append(subdomain)

    # Run Version Query
    version_query = run_dig_query("CH TXT version.bind", domain, dns_server)
    if version_query:
        write_output_to_file(os.path.join(domain_folder, "version-query.txt"), version_query)
        records.append(version_query)

    # Run ANY Query
    any_query = run_dig_query("any", domain, dns_server)
    if any_query:
        write_output_to_file(os.path.join(domain_folder, "any-query.txt"), any_query)
        records.append(any_query)
        subdomains = extract_subdomains(domain, any_query)

        if subdomains:
            for subdomain in subdomains:
                if subdomain not in universal_subdomains:
                    universal_subdomains.append(subdomain)

    # Run AXFR Zone Transfer
    axfr_query = run_dig_query("axfr", domain, dns_server)
    if axfr_query:
        write_output_to_file(os.path.join(domain_folder, "axfr-query.txt"), axfr_query)
        records.append(axfr_query)
        subdomains = extract_subdomains(domain, axfr_query)

        if subdomains:
            for subdomain in subdomains:
                if subdomain not in universal_subdomains:
                    universal_subdomains.append(subdomain)

    return records

def main():
    parser = argparse.ArgumentParser(description="DNS enumeration script using dig commands.")
    parser.add_argument("-target", help="Target IP address of the DNS server.")
    parser.add_argument("-domain", help="Domain to enumerate (required).")
    parser.add_argument("-port", type=int, default=53, help="DNS server port (default 53).")
    parser.add_argument("-wordlist", required=False, help="Path to subdomain wordlist.")
    parser.add_argument("-output-path", default="./dns-enum", help="Output folder path (default ./dns-enum).")
    
    args = parser.parse_args()

    # Ensure output path exists
    output_path = os.path.join(args.output_path)
    create_folder(output_path)

    # Ensure that domain and target are provided
    if not args.domain or not args.target:
        print("[ERROR] You must provide both a -target (DNS server IP) and a -domain (domain name).")
        return

    universal_subdomains.append(args.domain)
    for domain in universal_subdomains:
        # Perform DNS records enumeration on the main domain
        print(f"[INFO] Starting DNS enumeration for {domain} on DNS server {args.target}...")
        enumerate_dns_records(domain, args.target, output_path)

    with open("subdomains.txt", "a") as file:
        for subdomain in universal_subdomains:
            file.write(subdomain + '\n')

    # CALL dnsenum ON ALL DOMAINS FOUND
    print("Starting bruteforcing, please be patient this might take some time")
    for domain in universal_subdomains:
        command = ["dnsenum", "--enum", "--dnsserver", args.target, "-p", "0", "-s", "0", "-f", args.wordlist, domain, "--threads", "128"]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            print(f"Skipping {domain} (not viable)")
            continue
        subdomains = extract_subdomains(domain, output)
        if subdomains:

            for domain in subdomains:
                if domain.startswith("0m"):
                    domain = domain[2:]

                if domain not in bruted_subdomains:
                    bruted_subdomains.append(domain)

    # OUTPUT ALL NEWLY FOUND SUBDOMAINS 
    with open("subdomains.txt", 'a') as file:
        file.write("=======================================\n")
        for domain in bruted_subdomains:
            if domain not in universal_subdomains:
                file.write(f"{domain}\n")
            else:
                print(f"{domain} already exists at universal")

        file.write("=======================================\n")

    # RE-ENUMERATE ALL NEWLY FOUND SUBDOMAINS
    print("Re-Enumerating Found Subdomains")
    for domain in bruted_subdomains:
        if domain not in universal_subdomains:
            enumerate_dns_records(domain, args.target, output_path)

    print("[INFO] DNS enumeration completed.")

if __name__ == "__main__":
    main()

