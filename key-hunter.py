#!/usr/bin/env python3
import argparse
import subprocess
import re
import os
import sys
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Default regex pattern for sensitive data detection
DEFAULT_REGEX_PATTERN = r"""(?xi)\b(?P<var>(?:[A-Za-z0-9_]*(?:(?:api(?:_?key|_?secret))|(?:app(?:lication)?(?:_?key|_?secret))|(?:secret(?:_?key)?)|(?:(?:client|consumer)(?:_?key|_?secret)|client(?:_?id))|(?:(?:access|refresh|auth)(?:_?token))|(?:token(?:_?secret)?)|(?:oauth_consumer(?:_?key|_?secret))|(?:oauth_token(?:_?secret)?)|(?:(?:smtp|mail)_?password)|(?:login_?password)|(?:(?:password|passwd|pwd|passcode))|(?:(?:private|public)_?key)|(?:(?:encryption|decryption)_?key)|(?:keystore(?:_?password)?)|(?:keyPassword)|(?:storePassword)|(?:aws_(?:access_key_id|secret_access_key|session_token))|(?:amazon_(?:access_key|secret_key|session_token))|(?:firebase_?api_?key)|(?:google(?:_api_key|_maps_key))|(?:sentry_?dsn)|(?:auth(?:_?key))|(?:session(?:_?(?:token|id)))|(?:security_?token)|(?:certificate)|(?:ssl(?:_?cert(?:ificate)?))|(?:private(?:_?cert)|public(?:_?cert))|(?:basic)|(?:authorization))[A-Za-z0-9_]*|[A-Za-z0-9_]*?(?:URL|KEY|SECRET|PASSWORD|PASS|TOKEN)[A-Za-z0-9_]*)\b\s*=\s*["'](?=.{3,}["'])(?!(?:android|androidx|com\.facebook)\b)(?P<value>[^\s"';]+)["']\s*;?)"""

# File extensions to scan for sensitive data
SCAN_FILE_EXTENSIONS = (".java", ".kt", ".xml", ".smali", ".txt")

def run_command(cmd, ignore_error=False):
    """Execute a system command and return its stdout."""
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        if ignore_error:
            print(f"Warning: Command returned an error but proceeding anyway: {' '.join(cmd)}")
            return e.stdout
        else:
            print("Command failed:", e.stderr)
            sys.exit(1)

def list_packages(keyword):
    """List installed packages matching the keyword."""
    output = run_command(["adb", "shell", "pm", "list", "packages"])
    lines = output.splitlines()
    packages = [line.split("package:")[-1].strip() for line in lines if keyword.lower() in line.lower()]
    return packages

def choose_package(packages):
    """Interactively choose a package from a list."""
    print("\nSelect a package by number:")
    for idx, pkg in enumerate(packages):
        print(f"[{idx}] {pkg}")
    while True:
        selection = input("Enter the number of the package: ").strip()
        try:
            index = int(selection)
            if 0 <= index < len(packages):
                return packages[index]
            else:
                print("Invalid selection. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def get_apk_path(package_name):
    """Retrieve the APK path for a given package."""
    output = run_command(["adb", "shell", "pm", "path", package_name])
    lines = output.splitlines()
    if not lines:
        print("APK path not found for package:", package_name)
        sys.exit(1)
    apk_path = lines[0].split("package:")[-1].strip()
    return apk_path

def pull_apk(apk_path, package_name):
    """Pull the APK file from the device to the local machine."""
    apk_filename = f"{package_name}.apk"
    print(f"\nPulling APK from device: {apk_path} -> {apk_filename}")
    run_command(["adb", "pull", apk_path, apk_filename])
    return apk_filename

def decompile_apk(apk_filename, package_name):
    """Decompile the APK using jadx."""
    output_dir = f"{package_name}_decompiled"
    print(f"\nDecompiling APK with jadx into directory: {output_dir}")
    # Use ignore_error=True for JADX decompilation since minor errors might occur
    run_command(["jadx", "-d", output_dir, apk_filename], ignore_error=True)
    
    # Optionally, check if the output directory exists and has content
    if not os.path.isdir(output_dir) or not os.listdir(output_dir):
        print("Decompilation failed: Output directory is empty or does not exist.")
        sys.exit(1)
    return output_dir

def scan_file(file_path, regex):
    """Scan a single file for matches to the regex."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, start=1):
                if regex.search(line):
                    findings.append((file_path, i, line.strip()))
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
    return findings

def search_decompiled_source(output_dir, regex, num_threads):
    """Recursively scan decompiled files concurrently for sensitive data."""
    findings = []
    files_to_scan = []
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if file.lower().endswith(SCAN_FILE_EXTENSIONS):
                files_to_scan.append(os.path.join(root, file))
    
    print(f"\nScanning {len(files_to_scan)} files for sensitive patterns...")
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_file, file_path, regex): file_path for file_path in files_to_scan}
        for future in tqdm(as_completed(futures), total=len(files_to_scan), desc="Scanning files"):
            try:
                result = future.result()
                findings.extend(result)
            except Exception as e:
                print(f"Error processing file: {futures[future]} Error: {e}")
    return findings

def generate_report(package_name, findings):
    """Generate a fancy human-readable security report."""
    report_filename = f"{package_name}_security_report.txt"
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(report_filename, 'w', encoding='utf-8') as report:
        report.write("=" * 80 + "\n")
        report.write(f"Security Research Report for: {package_name}\n")
        report.write(f"Generated on: {now}\n")
        report.write("=" * 80 + "\n\n")
        if findings:
            report.write("Sensitive Data Findings:\n")
            report.write("-" * 80 + "\n")
            for file_path, line_number, line in findings:
                report.write(f"\n")
                report.write(f"File: {file_path}\n")
                report.write(f"Line {line_number}: {line}\n")
                report.write(f"\n")
                report.write("-" * 80 + "\n")
        else:
            report.write("No sensitive information found matching the specified patterns.\n")
    print(f"\nReport generated: {report_filename}")

def main():
    parser = argparse.ArgumentParser(description="Android Security Research Tool")
    parser.add_argument("--keyword", required=True,
                        help="Keyword to search for in package names")
    parser.add_argument("--package",
                        help="Full package name to analyze (if provided, skip keyword search)")
    parser.add_argument("--regex", default=DEFAULT_REGEX_PATTERN,
                        help="Custom regex pattern for sensitive data detection")
    parser.add_argument("--threads", type=int, default=4,
                        help="Number of threads for scanning files (default: 4)")
    args = parser.parse_args()

    # Compile regex pattern
    regex = re.compile(args.regex)

    # Package selection: either use provided package or search by keyword.
    if args.package:
        selected_package = args.package
    else:
        packages = list_packages(args.keyword)
        if not packages:
            print(f"\nNo packages found with keyword: {args.keyword}")
            sys.exit(0)
        print("\nPackages found:")
        for idx, pkg in enumerate(packages):
            print(f"[{idx}] {pkg}")
        selected_package = choose_package(packages)

    print(f"\nSelected package: {selected_package}")

    # Retrieve APK, decompile, and scan for sensitive patterns.
    apk_path = get_apk_path(selected_package)
    apk_filename = pull_apk(apk_path, selected_package)
    decompiled_dir = decompile_apk(apk_filename, selected_package)
    findings = search_decompiled_source(decompiled_dir, regex, args.threads)
    generate_report(selected_package, findings)

if __name__ == "__main__":
    main()
