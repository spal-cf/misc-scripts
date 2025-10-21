import subprocess
from datetime import datetime
import re
import os
import zipfile
from pathlib import Path

pkg_id = "com.google.android.apps.cloudconsole"

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
           
def run_rabin2_and_grep(path: Path, pattern: str):
    # Run rabin2 -I <file>
    proc = subprocess.run(
        ["rabin2", "-I", str(path)],
        capture_output=True,
        text=True
    )
    # If rabin2 failed, return stderr info
    if proc.returncode != 0 and not proc.stdout:
        return {"error": proc.stderr.strip() or f"rabin2 exited {proc.returncode}"}
    # Filter stdout lines by regex pattern
    matches = [line for line in proc.stdout.splitlines() if re.search(pattern, line)]
    return {"matches": matches, "stdout": proc.stdout, "stderr": proc.stderr}
    
def check_pattern(pattern: str):
    if shutil.which("rabin2") is None:
        print("Error: rabin2 not found in PATH. Install radare2 / rabin2 and try again.", file=sys.stderr)
        sys.exit(2)
        
    d = Path("apks/Payload")
    if not d.exists() or not d.is_dir():
        print(f"Error: directory not found: {d}", file=sys.stderr)
        sys.exit(1)

    # iterate files (non-recursive) in lexicographic order
    for p in sorted(d.iterdir()):
        # skip directories; mimic ls behavior that lists entries
        if p.is_dir():
            continue
        print(p.name)
        #pattern = ""
        res = run_rabin2_and_grep(p, pattern)
        if "error" in res:
            print(f"  [rabin2 error] {res['error']}")
            continue
        if res["matches"]:
            for m in res["matches"]:
                print(m)
        else:
            if args.all:
                # optionally show full output if requested
                print(res["stdout"].rstrip())
            # otherwise print nothing (same behavior as piping to grep with no matches)

    
# Example usage
if __name__ == "__main__":
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
        
    apk_dir = "apks"
    os.makedirs(apk_dir, exist_ok=True)
    run_command("apksigner verify -v --print-certs apks/base.apk")
    #extract_apk('apks/base.apk', 'apks/Payload')
    run_command("apktool d apks/base.apk  -o apks/Payload")
    run_command("aapt d badging apks/base.apk")
    
    run_command("find ./ -name AndroidManifest.xml")
    run_command("find ./ -name data_extraction_rules.xml") 
    run_command("find ./ -name backup_rules.xml") 
    run_command("grep -i backup apks/Payload/AndroidManifest.xml") 
    run_command("grep -i fullBackupContent apks/Payload/AndroidManifest.xml")
    run_command("grep -i dataExtractionRules apks/Payload/AndroidManifest.xml")
    run_command("grep -i debuggable apks/Payload/AndroidManifest.xml")
    run_command("cat apks/Payload/apktool.yml | grep -i -A2 sdkinfo")
    
    run_command("apkid apks/base.apk")
    
    out_dir = "out"
    os.makedirs(apk_dir, exist_ok=True)
    run_command("grep -ri shell apks/Payload/* --color=always > out/shell.txt")
    run_command("grep -ri api apks/Payload/* --color=always > out/api.txt")
    run_command("grep -ri database apks/Payload/* --color=always > out/database.txt")
    run_command("grep -ri query apks/Payload/* --color=always > out/query.txt")
    run_command("grep -ri post apks/Payload/* --color=always > out/post.txt")
    run_command("grep -ri get apks/Payload/* --color=always > out/get.txt")
    run_command("grep -ri config apks/Payload/* --color=always > out/config.txt")
    run_command("grep -ri auth apks/Payload/* --color=always > out/auth.txt")
    run_command("grep -ri secret apks/Payload/* --color=always > out/secret.txt")
    run_command("grep -ri password apks/Payload/* --color=always > out/password.txt")
    run_command("grep -ri singleton apks/Payload/* --color=always > out/singleton.txt")
    run_command("grep -ri http apks/Payload/* --color=always > out/http.txt")
    run_command("grep -ri https apks/Payload/* --color=always > out/https.txt")
    run_command("grep -ri key apks/Payload/* --color=always > out/key.txt")
    
    run_command("adb shell dumpsys package " + pkg_id)
    #run_command("adb shell am start -W -n " + pkg_id)
    
    pkg = run_command("aapt dump badging apks/base.apk|awk -F\" \" '/package/ {print $2}'|awk -F\"'\" '/name=/ {print $2}'")
    act = run_command("aapt dump badging apks/base.apk|awk -F\" \" '/launchable-activity/ {print $2}'|awk -F\"'\" '/name=/ {print $2}'")
    print (pkg)
    print(act)
    run_command("adb shell am start -W -n " + pkg + "/" + act)
    run_command("adb shell dumpsys meminfo | tee mem.txt")
    
    
