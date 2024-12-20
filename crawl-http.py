import argparse
import re
import os
import json
import subprocess
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin
import socket

targets = []


def is_ip(target):
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False

def check_robots_sitemap(url, output_path):
    for path in ["robots.txt", "sitemap.xml"]:
        file_url = urljoin(url, path)
        response = requests.get(file_url)
        if response.status_code == 200:
            print(f"[+] Found {path} at {file_url}")
            with open(os.path.join(output_path, f"{path}"), "w") as f:
                f.write(response.text)

def crawl_page(url, output_path):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Hidden elements
    hidden_elements = soup.find_all(style=re.compile(r"display\s*:\s*none"))
    with open(os.path.join(output_path, "hidden_elements.txt"), "a") as f:
        for element in hidden_elements:
            f.write(f"Found hidden element: {element}\n")
    
    # Comments
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    with open(os.path.join(output_path, "comments.txt"), "a") as f:
        for comment in comments:
            f.write(f"Found comment: {comment}\n")

    # Directory listing check (<script> tag)
    links = soup.find_all("script", src=True)
    checked_dirs = set()
    for link in links:
        href = link['src']
        if href and not href.isspace() and "http://" not in href and "https://" not in href:
            dir_url = urljoin(url, href)
            dir_path = os.path.dirname(dir_url)
            if dir_path and dir_path not in targets:
                targets.append(dir_path)
            if dir_path and dir_path not in checked_dirs:
                dir_response = requests.get(dir_path)
                if dir_response.status_code == 200 and "Index of" in dir_response.text:
                    print(f"[+] Directory listing enabled at {dir_path}")
                    with open(os.path.join(output_path, "directory_listing.txt"), "a") as f:
                        f.write(f"Directory listing enabled at: {dir_path}\n")
                checked_dirs.add(dir_path)

    # Directory listing check (<link> tag)
    links = soup.find_all("link", href=True)
    for link in links:
        href = link['href']
        if href and not href.isspace() and "http://" not in href and "https://" not in href:
            dir_url = urljoin(url, href)
            dir_path = os.path.dirname(dir_url)
            if dir_path and dir_path not in targets:
                targets.append(dir_path)
            if dir_path and dir_path not in checked_dirs:
                dir_response = requests.get(dir_path)
                if dir_response.status_code == 200 and "Index of" in dir_response.text:
                    print(f"[+] Directory listing enabled at {dir_path}")
                    with open(os.path.join(output_path, "directory_listing.txt"), "a") as f:
                        f.write(f"Directory listing enabled at: {dir_path}\n")
                checked_dirs.add(dir_path)

    # Directory listing check (<img> tag)
    links = soup.find_all("img", src=True)
    for link in links:
        href = link['src']
        if href and not href.isspace() and "http://" not in href and "https://" not in href:
            dir_url = urljoin(url, href)
            dir_path = os.path.dirname(dir_url)
            if dir_path and dir_path not in targets:
                targets.append(dir_path)
            if dir_path and dir_path not in checked_dirs:
                dir_response = requests.get(dir_path)
                if dir_response.status_code == 200 and "Index of" in dir_response.text:
                    print(f"[+] Directory listing enabled at {dir_path}")
                    with open(os.path.join(output_path, "directory_listing.txt"), "a") as f:
                        f.write(f"Directory listing enabled at: {dir_path}\n")
                checked_dirs.add(dir_path)

    # Directory listing check (<a> tag)
    links = soup.find_all("a", href=True)
    for link in links:
        href = link['href']
        if href and not href.isspace() and "http://" not in href and "https://" not in href:
            dir_url = urljoin(url, href)
            dir_path = os.path.dirname(dir_url)
            if dir_path and dir_path not in targets:
                targets.append(dir_path)
            if dir_path and dir_path not in checked_dirs:
                dir_response = requests.get(dir_path)
                if dir_response.status_code == 200 and "Index of" in dir_response.text:
                    print(f"[+] Directory listing enabled at {dir_path}")
                    with open(os.path.join(output_path, "directory_listing.txt"), "a") as f:
                        f.write(f"Directory listing enabled at: {dir_path}\n")
                checked_dirs.add(dir_path)

def run_ffuf(target, output_path, wordlist, threads):
    if is_ip(target):
        print("[*] Target is an IP address, skipping FFUF subdomain enumeration.")
        return

    if not wordlist:
        print("[-] Error: FFUF wordlist is not specified.")
        return

    # First run: Get baseline response metrics
    print("[*] Running FFUF for baseline response characteristics...")
    ffuf_cmd = [
        "ffuf", "-u", f"http://{target}/", "-H", f"Host: FUZZ.{target}",
        "-w", wordlist, "-t", "1", "-maxtime", "1"
    ]
    
    result = subprocess.run(ffuf_cmd, capture_output=True, text=True)
    baseline_responses = result.stdout

    # Extract the typical response length or word count from the initial output
    response_sizes = re.findall(r"Size: (\d+)", baseline_responses)
    response_words = re.findall(r"Words: (\d+)", baseline_responses)
    response_lines = re.findall(r"Lines: (\d+)", baseline_responses)
    if response_sizes and len(set(response_sizes)) == 1:
        common_value = f"-fs {response_sizes[0]}"
        print(f"ffuf Found Size {common_value} a common value")

    elif response_words and len(set(response_words)) == 1:
        common_value = f"-fw {response_words[0]}"
        print(f"ffuf Found Words Count {common_value} a common value")

    elif response_lines and len(set(response_lines)) == 1:
        common_value = f"-fl {response_lines[0]}"
        print(f"ffuf Found Lines Count {common_value} a common value")

    else:
        print("[-] Error: Could not determine a common value.")
        return

    # Second run: FFUF with filtered responses
    print(f"[*] Re-running FFUF with filter -fs {common_value} to exclude false positives...")
    ffuf_cmd_filtered = [
        "ffuf", "-u", f"http://{target}/", "-H", f"Host: FUZZ.{target}",
        "-w", wordlist, "-o", os.path.join(output_path, "ffuf_output.txt"),
        "-t", str(threads), *common_value.split()  # Filter by common value
    ]
    subprocess.run(ffuf_cmd_filtered)

    file = open("crawled-http/ffuf_output.txt", 'r')
    content = file.read()
    file.close()

    data = json.loads(content)

    inner = None
    for value in data.values():
        if type(value) == list:
            inner = value
            break

    subdomains = []
    for item in inner:
        subdomain = item.get("host")
        if subdomain:
            subdomains.append(subdomain)

    file = open("crawled-http/subdomains.txt", 'a')
    for subdomain in subdomains:
        file.write(f"Found {subdomain}\n")

    file.close()


def run_dirsearch(target, port, output_path, wordlist, threads, exclude_status):
    print(f"[*] Running Dirsearch for directory discovery on {target}:{port}")

    if exclude_status:
        dirsearch_cmd = [
            "dirsearch", "-u", f"http://{target}:{port}",
            "-e", "html,md,txt,php,bak",
            "-f",
            "-r",
            "-o", os.path.join(output_path, f"dirsearch.txt"),
            "--recursion-status=200,403",
            "-t", str(threads),
            f"--exclude-status={exclude_status}"
        ]
    else:
        dirsearch_cmd = [
            "dirsearch", "-u", f"http://{target}:{port}",
            "-e", "html,md,txt,php,bak",
            "-f",
            "-r",
            "-o", os.path.join(output_path, f"dirsearch.txt"),
            "--recursion-status=200,403",
            "-t", str(threads)
        ]
    
    if wordlist:
        dirsearch_cmd.extend(["-w", wordlist])

    subprocess.run(dirsearch_cmd)


def test_path_traversal(target, output_path):
    print("[*] Testing for path traversal vulnerabilities...")
    traversal_attempts = ["../" * i + "etc/passwd" for i in range(1, 8)]
    traversal_attempts
    with open(os.path.join(output_path, "path_traversal.txt"), "a") as f:
        for attempt in traversal_attempts:
            traversal_url = f"{target}{attempt}"
            response = subprocess.run(
                ["curl", "--path-as-is", traversal_url],
                capture_output=True, text=True
            )
            if "root:" in response.stdout:
                f.write(f"[+] Potential path traversal found at: {traversal_url}\n")
                print(f"[+] Potential path traversal found at: {traversal_url}")

            traversal_url_2 = f"{target}/{attempt}"
            response = subprocess.run(
                ["curl", "--path-as-is", traversal_url_2],
                capture_output=True, text=True
            )
            if "root:" in response.stdout:
                f.write(f"[+] Potential path traversal found at: {traversal_url_2}\n")
                print(f"[+] Potential path traversal found at: {traversal_url_2}")

def main():
    parser = argparse.ArgumentParser(description="Web Crawler with Pentesting Enhancements")
    parser.add_argument("-target", required=True, help="Target URL (e.g., http://example.com or IP address)")
    parser.add_argument("-output-path", default="", help="Path to save output files (default '')")
    parser.add_argument("-port", default=80, type=int, help="Port of the target (default: 80)")
    parser.add_argument("-ffuf-wordlist", help="Wordlist for FFUF subdomain enumeration")
    parser.add_argument("-dirsearch-wordlist", help="Wordlist for Dirsearch directory discovery")
    parser.add_argument("-threads", type=int, default=128, help="Number of threads for FFUF and Dirsearch (default: 128)")
    parser.add_argument("-exclude-status", help="Status codes to exclude in Dirsearch, e.g., 403,404", default="400,403,404")
    
    args = parser.parse_args()

    output_path = os.path.join(args.output_path, "crawled-http")
    os.makedirs(output_path, exist_ok=True)

    target_url = f"http://{args.target}:{args.port}" if args.port != 80 else f"http://{args.target}"
    targets.append(target_url)

    check_robots_sitemap(target_url, output_path)
    run_ffuf(args.target, output_path, args.ffuf_wordlist, args.threads)

    for target in targets:
        test_path_traversal(target, output_path)
        crawl_page(target, output_path)

    file = open(os.path.join(output_path, "directories_found.txt"), "a")
    for target in targets:
        file.write(f"{target}\n")
    file.close()

    run_dirsearch(args.target, args.port, output_path, args.dirsearch_wordlist, args.threads, args.exclude_status)

if __name__ == "__main__":
    main()

