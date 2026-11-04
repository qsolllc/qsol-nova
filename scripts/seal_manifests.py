import hashlib
from pathlib import Path
import json
import datetime
import subprocess
import shutil

TARGET_GLOBS = [
    "scripts/**/*.py",
    "src/**/*.rs",
    "*.json",
    "*.toml"
]

def compute_sha3_512(file_path: Path, chunk_size: int = 65536) -> str:
    sha3 = hashlib.sha3_512()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha3.update(chunk)
    return sha3.hexdigest()

def stamp_with_opentimestamps(manifest_path: Path):
    ots_executable = shutil.which("ots")
    if not ots_executable:
        print("[!] Warning: 'ots' command-line tool not found. Skipping blockchain timestamping.")
        return

    print(f"[*] Submitting {manifest_path.name} to OpenTimestamps calendar servers...")
    try:
        subprocess.run(
            ["ots", "stamp", str(manifest_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        print(f"[+] OpenTimestamps proof successfully created: {manifest_path.name}.ots")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: Failed to generate OpenTimestamps proof: {e.stderr.strip()}")

def generate_sealed_manifest():
    repo_root = Path.cwd()
    artifacts = []
    
    print(f"[*] Scanning {repo_root.name} for cryptographic sealing...")
    
    seen_files = set()
    for pattern in TARGET_GLOBS:
        for file_path in repo_root.glob(pattern):
            if file_path.is_file() and ".git" not in file_path.parts:
                resolved_path = file_path.resolve()
                if resolved_path in seen_files:
                    continue
                seen_files.add(resolved_path)
                
                rel_path = file_path.relative_to(repo_root)
                file_hash = compute_sha3_512(resolved_path)
                
                artifacts.append({
                    "path": str(rel_path).replace("\\", "/"),
                    "sha3_512": file_hash
                })
                
    manifest_data = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "algorithm": "SHA3-512",
        "artifact_count": len(artifacts),
        "artifacts": sorted(artifacts, key=lambda x: x["path"])
    }
    
    manifest_output_path = repo_root / "sealed_manifest.json"
    with open(manifest_output_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)
        
    print(f"[+] Sealed manifest generated: {len(artifacts)} artifacts secured.")
    stamp_with_opentimestamps(manifest_output_path)

if __name__ == "__main__":
    generate_sealed_manifest()
