#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "=== 1. build ==="
cargo build --release

echo
echo "=== 2. manifest ==="
sha256sum -c MANIFEST.sha256

echo
echo "=== 3. Pedersen fold ==="
./target/release/qsol-nova | grep -E "FOLD_VALID|TAMPER_DETECTED"

echo
echo "=== 4. R1CS fold ==="
./target/release/fold_r1cs | grep -E "FOLD_VALID|TAMPER"

echo
echo "=== 5. Committed fold ==="
./target/release/fold_committed | grep -E "FOLD_VALID|TAMPER|Folded R1CS"

echo
echo "ALL FOLDS VERIFIED"
