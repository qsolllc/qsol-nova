import hashlib
from pathlib import Path
import json
import sys

def normalize_path(uri_or_path: str) -> Path:
    clean_str = uri_or_path.strip()
    if clean_str.startswith("file:///"):
        clean_str = clean_str[8:] if len(clean_str) > 8 and clean_str[9] == ":" else clean_str[7:]
    elif clean_str.startswith("file://"):
        clean_str = clean_str[7:]
    return Path(clean_str).resolve()

def compute_sha3_512(file_path: Path, chunk_size: int = 65536) -> str:
    sha3 = hashlib.sha3_512()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha3.update(chunk)
    return sha3.hexdigest()

def audit_manifest(manifest_path: str):
    manifest_file = Path(manifest_path).resolve()
    if not manifest_file.exists():
        raise FileNotFoundError(f"Manifest path not found: {manifest_file}")

    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    discrepancies = []
    artifacts = manifest_data.get("artifacts", [])

    for entry in artifacts:
        raw_path = entry.get("path") or entry.get("fileUri")
        expected_hash = entry.get("sha3_512")

        if not raw_path or not expected_hash:
            continue

        target_path = normalize_path(raw_path)

        if not target_path.exists():
            discrepancies.append({"path": str(target_path), "status": "MISSING"})
            continue

        actual_hash = compute_sha3_512(target_path)
        if actual_hash != expected_hash:
            discrepancies.append({
                "path": str(target_path),
                "status": "HASH_MISMATCH",
                "expected": expected_hash,
                "actual": actual_hash
            })

    return discrepancies

if __name__ == "__main__":
    manifest_target = "sealed_manifest.json"
    try:
        if not Path(manifest_target).exists():
            print(f"[!] Warning: Baseline manifest '{manifest_target}' not found. Skipping strict audit.")
            sys.exit(0)

        issues = audit_manifest(manifest_target)
        if issues:
            print(f"[FATAL] Integrity verification failed! Detected {len(issues)} discrepancies.")
            for issue in issues:
                print(f"  - {issue['path']} [{issue['status']}]")
            sys.exit(1)
        else:
            print("[SUCCESS] All artifacts verified successfully.")
            sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Execution aborted: {e}")
        sys.exit(2)
