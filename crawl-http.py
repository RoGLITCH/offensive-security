import argparse
import re
import os
import subprocess
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin
import socket

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
    with open(os.path.join(output_path, "hidden_elements.txt"), "w") as f:
        for element in hidden_elements:
            f.write(f"Found hidden element: {element}\n")
    
    # Comments
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    with open(os.path.join(output_path, "comments.txt"), "w") as f:
        for comment in comments:
            f.write(f"Found comment: {comment}\n")

    # Directory listing check
    links = soup.find_all("a", href=True)
    checked_dirs = set()
    for link in links:
        href = link['href']
        if href.startswith('/'):
            dir_url = urljoin(url, href)
            dir_path = os.path.dirname(dir_url)
            if dir_path not in checked_dirs:
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

    print("[*] Running FFUF for subdomain enumeration...")
    ffuf_cmd = [
        "ffuf", "-u", f"http://{target}/", "-H", f"Host: FUZZ.{target}",
        "-w", wordlist, "-o", os.path.join(output_path, "subdomains.txt"),
        "-t", str(threads)
    ]
    subprocess.run(ffuf_cmd)

def run_dirsearch(target, port, output_path, wordlist, threads, exclude_status):
    print(f"[*] Running Dirsearch for directory discovery on {target}:{port}")

    if exclude_status:
        dirsearch_cmd = [
            "dirsearch", "-u", f"http://{target}:{port}",
            "-e", "html,md,txt,php,bak",
            "-f",
            "-r",
            "-o", os.path.join(output_path, f"directories_found.txt"),
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
            "-o", os.path.join(output_path, f"directories_found.txt"),
            "--recursion-status=200,403",
            "-t", str(threads)
        ]
    
    if wordlist:
        dirsearch_cmd.extend(["-w", wordlist])

    subprocess.run(dirsearch_cmd)


def test_path_traversal(target, output_path):
    print("[*] Testing for path traversal vulnerabilities...")
    traversal_attempts = ["/" + "../" * i + "etc/passwd" for i in range(1, 8)]
    with open(os.path.join(output_path, "path_traversal.txt"), "w") as f:
        for attempt in traversal_attempts:
            traversal_url = f"http://{target}{attempt}"
            response = subprocess.run(
                ["curl", "--path-as-is", traversal_url],
                capture_output=True, text=True
            )
            if "root:" in response.stdout:
                f.write(f"[+] Potential path traversal found at: {traversal_url}\n")
                print(f"[+] Potential path traversal found at: {traversal_url}")
            else:
                f.write(f"[-] No path traversal at: {traversal_url}\n")

def main():
    parser = argparse.ArgumentParser(description="Web Crawler with Pentesting Enhancements")
    parser.add_argument("-target", required=True, help="Target URL (e.g., http://example.com or IP address)")
    parser.add_argument("-output-path", required=True, help="Path to save output files")
    parser.add_argument("-port", default=80, type=int, help="Port of the target (default: 80)")
    parser.add_argument("-ffuf-wordlist", help="Wordlist for FFUF subdomain enumeration")
    parser.add_argument("-dirsearch-wordlist", help="Wordlist for Dirsearch directory discovery")
    parser.add_argument("-threads", type=int, default=10, help="Number of threads for FFUF and Dirsearch (default: 10)")
    parser.add_argument("-exclude-status", help="Status codes to exclude in Dirsearch, e.g., 403,404", default="403,404")
    
    args = parser.parse_args()

    output_path = os.path.join(args.output_path, "crawled-http")
    os.makedirs(output_path, exist_ok=True)

    target_url = f"http://{args.target}:{args.port}" if args.port != 80 else f"http://{args.target}"

    check_robots_sitemap(target_url, output_path)
    crawl_page(target_url, output_path)

    run_ffuf(args.target, output_path, args.ffuf_wordlist, args.threads)
    run_dirsearch(args.target, args.port, output_path, args.dirsearch_wordlist, args.threads, args.exclude_status)
    test_path_traversal(args.target, output_path)

if __name__ == "__main__":
    main()

