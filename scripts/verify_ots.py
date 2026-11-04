#!/usr/bin/env python3
import subprocess
import shutil
import sys
from pathlib import Path

def verify_ots_proofs():
    ots_executable = shutil.which("ots")
    if not ots_executable:
        print("[!] Error: 'ots' command-line tool not found.")
        print("    Install via: pip install opentimestamps-client")
        sys.exit(2)

    repo_root = Path.cwd()
    ots_files = list(repo_root.rglob("*.ots"))

    if not ots_files:
        print("[*] No OpenTimestamps (.ots) proof files found in the repository.")
        sys.exit(0)

    print(f"[*] Found {len(ots_files)} OpenTimestamps proof(s). Verifying against the Bitcoin network...")
    
    failures = 0
    successes = 0
    pending = 0

    for ots_path in ots_files:
        print(f"\n--------------------------------------------------")
        print(f"[*] Verifying proof: {ots_path.relative_to(repo_root)}")
        
        try:
            result = subprocess.run(
                ["ots", "verify", str(ots_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            print(result.stdout.strip())
            print(f"[+] SUCCESS: Proof verified successfully.")
            successes += 1
        except subprocess.CalledProcessError as e:
            output = e.stdout + e.stderr
            print(output.strip())
            if "pending" in output.lower():
                print(f"[!] PENDING: Proof is awaiting Bitcoin calendar aggregation/confirmation.")
                pending += 1
            else:
                print(f"[X] FAILED: Cryptographic verification failed!")
                failures += 1

    print(f"\n==================================================")
    print(f"[*] Verification Summary:")
    print(f"    - Total Proofs Scanned : {len(ots_files)}")
    print(f"    - Successfully Verified: {successes}")
    print(f"    - Pending Confirmation : {pending}")
    print(f"    - Failed / Invalid     : {failures}")
    print(f"==================================================")

    if failures > 0:
        print("[FATAL] Security audit failed: One or more OTS proofs are invalid.")
        sys.exit(1)
    else:
        print("[SUCCESS] All evaluated OpenTimestamps proofs passed integrity checks.")
        sys.exit(0)

if __name__ == "__main__":
    verify_ots_proofs()
