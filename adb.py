import subprocess
from datetime import datetime
import re
import os
import zipfile

def sanitize_filename(name: str) -> str:
    """
    Sanitize command string to be safe for filenames.
    Removes/replace characters like /, |, >, etc.
    """
    return re.sub(r'[^a-zA-Z0-9._-]+', '_', name).strip("_")


def run_command(cmd, output_dir="command_logs"):
    try:
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Create unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = sanitize_filename(cmd[:50])  # limit length
        filename = f"{safe_name}_{timestamp}.log"
        filepath = os.path.join(output_dir, filename)

        # Run the command
        result = subprocess.run(
            cmd,
            shell=True,
            text=True,
            capture_output=True,
            check=True
        )

        output_text = (
            f"=== {datetime.now()} ===\n"
            f"Command: {cmd}\n"
            f"Return Code: 0\n"
            f"STDOUT:\n{result.stdout.strip()}\n\n"
        )

        with open(filepath, "w") as f:
            f.write(output_text)

        print(f"✅ Command executed successfully. Output written to: {filepath}")
        return result.stdout.strip()

    except subprocess.CalledProcessError as e:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = sanitize_filename(cmd[:50])
        filename = f"{safe_name}_{timestamp}.log"
        filepath = os.path.join(output_dir, filename)

        error_text = (
            f"=== {datetime.now()} ===\n"
            f"Command: {cmd}\n"
            f"Return Code: {e.returncode}\n"
            f"STDOUT:\n{e.stdout.strip()}\n"
            f"STDERR:\n{e.stderr.strip()}\n\n"
        )

        with open(filepath, "w") as f:
            f.write(error_text)

        print(f"❌ Command failed. Error written to: {filepath}")
        return None

    except Exception as e:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = sanitize_filename(cmd[:50])
        filename = f"{safe_name}_{timestamp}.log"
        filepath = os.path.join(output_dir, filename)

        error_text = (
            f"=== {datetime.now()} ===\n"
            f"Command: {cmd}\n"
            f"Unexpected Error: {str(e)}\n\n"
        )

        with open(filepath, "w") as f:
            f.write(error_text)

        print(f"⚠️ Unexpected error logged in: {filepath}")
        return None


def extract_apk_files_from_file(file_path: str):
    """
    Reads a text file and extracts .apk file paths.
    Returns a list of unique .apk matches.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception as e:
        print(f"⚠️ Error reading file {file_path}: {e}")
        return []

    # Regex: match anything ending with .apk
    #apk_pattern = re.compile(r'[\w./:=+-]+\.apk', re.IGNORECASE)
    apk_pattern = re.compile(r"/data/app/[^\s]+\.apk", re.IGNORECASE)
    matches = apk_pattern.findall(text)

    # Remove duplicates while preserving order
    seen = set()
    apk_files = []
    for m in matches:
        if m not in seen:
            print(m)
            seen.add(m)
            apk_files.append(m)

    return apk_files

def extract_apk_files(text: str):
    """
    Extract .apk file paths from adb output logs or generic text.
    Returns a list of unique .apk paths.
    """
    # Regex matches anything ending in .apk (case-insensitive)
    #apk_pattern = re.compile(r'[\w./:=+-]+\.apk', re.IGNORECASE)
    apk_pattern = re.compile(r"/data/app/[^\s]+\.apk", re.IGNORECASE)

    matches = apk_pattern.findall(text)

    # Remove duplicates while preserving order
    seen = set()
    apk_files = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            apk_files.append(m)

    return apk_files
 
 
def extract_apk(apk_path, output_dir):
    """
    Extracts the contents of an APK file (APK is just a ZIP archive).
    """
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk:
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Extract all files
            apk.extractall(output_dir)
            print(f"✅ Extracted APK to: {output_dir}")
            return True
    except zipfile.BadZipFile:
        print("❌ Error: The APK file is not a valid ZIP archive.")
        return False
    except Exception as e:
        print(f"⚠️ Unexpected error: {e}")
        return False
           

# Example usage
if __name__ == "__main__":
    pkg_id = "com.google.android.apps.giant"
    run_command("adb shell pm list packages | grep -i " + pkg_id)
    apk_files = run_command("adb shell pm path " + pkg_id)
    print("")
    print(apk_files)
    apks = extract_apk_files(apk_files)
    
    apk_dir = "apks"
    os.makedirs(apk_dir, exist_ok=True)

    if apks:
        print("✅ Extracted APK files:")
        for apk in apks:
            print(apk)
            run_command("adb pull " + apk + " apks/")
    else:
        print("❌ No APK files found.")
        
    #apk_dir = "apks"
    #os.makedirs(apk_dir, exist_ok=True)
    run_command("apksigner verify -v --print-certs apks/base.apk")
    #extract_apk('apks/base.apk', 'apks/Payload')
    run_command("apktool d apks/base.apk  -o apks/analytics")
    run_command("aapt d badging apks/base.apk")
    run_command("adb shell dumpsys package " + pkg_id)
    run_command("adb shell dumpsys meminfo" )
