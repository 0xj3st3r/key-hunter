# key-hunte - Android Security Research Tool

This tool automates the process of searching for sensitive keys and tokens in Android APKs by:

- Listing installed packages on an Android device via ADB.
- Pulling the APK for a selected package.
- Decompiling the APK using JADX.
- Scanning the decompiled source code for sensitive assignments (e.g. API keys, secrets, URLs) using an optimized regex that even excludes values starting with "android".
- Generating a human-readable report of the findings.

## Prerequisites

Before running the tool, ensure you have the following installed and configured:

- **Python 3.x**  
  Download and install Python 3 from [python.org](https://www.python.org/).

- **Android Debug Bridge (adb)**  
  Install ADB and make sure it's available in your system PATH. See the [ADB documentation](https://developer.android.com/studio/command-line/adb) for details.

- **jadx**  
  Download and install JADX from its [GitHub repository](https://github.com/skylot/jadx). Ensure that the `jadx` command is accessible in your system PATH.

- **Python Dependencies**  
  The tool uses the `tqdm` package for progress indicators. Other dependencies are part of the Python Standard Library.

## Setting Up and Launching in a Virtual Environment

1. **Create a Virtual Environment**  
   Navigate to the project directory and create a new virtual environment:
   ```bash
   python -m venv venv
   ```
2. **Activate the Virtual Environment**  
   - **On Windows:**
     ```bash
     venv\Scripts\activate
     ```
   - **On macOS/Linux:**
     ```bash
     source venv/bin/activate
     ```

3. **Install Required Python Packages**  
   With the virtual environment activated, install the `tqdm` package:
   ```bash
   pip install tqdm
   ```

## How to Use the Tool

1. **Run the Tool with a Package Keyword**  
   The tool can search for installed packages that contain a specified keyword. For example, to search for packages containing the keyword "example" using 4 threads:
   ```bash
   python security_tool.py --keyword example --threads 4
   ```
2. **Selecting a Package**
   - If the --package argument is not provided, the tool will list matching packages.
   - You will be prompted to select a package by entering its corresponding number.
   - If no packages are found with the provided keyword, the tool will output a message and exit.

3. **APK Extraction, Decompilation, and Scanning**
   - The tool uses ADB to retrieve the APK path for the selected package and pulls the APK to your local machine.
   - It then decompiles the APK using JADX into a directory named `<package_name>_decompiled`
   - The decompiled source code is scanned using an optimized regex to identify assignments that potentially contain sensitive data.

4. **Custom Regex**
   If you wish to use a custom regex pattern, pass it using the --regex parameter:
   ```bash
   python security_tool.py --keyword example --regex 'your_custom_regex_here'
   ```

## Example

```bash
   python security_tool.py --keyword meest --threads 8
```
After running the command, you will see a list of matching packages. Enter the number corresponding to the package you want to analyze. The tool will then pull, decompile, scan the APK, and generate a report with its findings.

## Feel free to create pull requests to adjust RegExp with your findings

