# QSOL Nova

Folding-based proof aggregation on the Pallas elliptic curve.

Three independent binaries demonstrating progressively stronger
folding constructions. Each produces hash-anchored evidence and a
tamper test. All run on commodity Android hardware (Termux, Galaxy
S25 FE) in single-digit milliseconds.

## The three constructions

### 1. `qsol-nova` — Pedersen commitment folding

Proves that a linear combination of two Pedersen commitments equals
the commitment of the folded witness.

    C1 = a1·G + b1·H + s1·R
    C2 = a2·G + b2·H + s2·R
    rho = SHA3-512(C1, C2)
    C_folded = C1 + rho·C2

    FOLD_VALID        = true
    TAMPER_DETECTED   = true

### 2. `fold_r1cs` — Nova-style relaxed R1CS fold

Implements the folding scheme from the Nova paper §4 over a small
R1CS circuit (`w1 · w2 = x`). Computes the cross-term and verifies
the folded relaxed instance.

    T = a1·b2 + a2·b1 − u1·c2 − u2·c1        (cross-term)
    u_f = u1 + rho·u2
    E_f = E1 + rho·T + rho²·E2
    z_f = z1 + rho·z2

    Folded R1CS: a·z_f ∘ b·z_f  ==  u_f·c·z_f + E_f

    FOLD_VALID        = true
    TAMPER_E_DETECTED = true
    TAMPER_Z_DETECTED = true

### 3. `fold_committed` — Nova fold with hidden witness

Same as (2) but the verifier's challenge is derived from the
commitments, not from the plain witness. The verifier never receives
`z`, `E`, or the folded witness — only commitments.

    rho = SHA3-512(C1, C2)              (from commitments)
    C_folded = C1 + rho·C2              (verifier computes this)
    Prover's check: witness-side fold commits to the same point

    FOLD_VALID                       = true
    TAMPER_DETECTED                  = true
    Folded R1CS satisfied            = true
    Verifier sees witness            = false

## What these are not

This is not full Nova IVC. The three constructions here provide:

- Pedersen folding (linear)
- Relaxed R1CS folding with cross-term
- Committed-witness folding

Not yet implemented:

- Iteration (N instances folded to 1 accumulator)
- Spartan compression (short final proof)

Those are the remaining pieces to reach a complete IVC system.
This repository does not claim them.

## Verification

Requires Rust (any stable 1.75+).

    cargo build --release
    ./target/release/qsol-nova
    ./target/release/fold_r1cs
    ./target/release/fold_committed

Each binary prints `FOLD_VALID = true`, tamper checks, and a
SHA3-512 evidence hash over its own output. Evidence files under
`evidence/` are hash-anchored by `MANIFEST.sha256`.

Reproduce everything:

    ./verify.sh

## Evidence

Two `.dat` files under `evidence/`, each with a matching `.sig`
containing a SHA3-512 hash of the `.dat` content. The `MANIFEST.sha256`
file at the root hashes every source file and every evidence file.

## Curve

Pallas, from the Pasta cycle (`pasta_curves` 0.5). The Pasta cycle is
the curve family used by Mina Protocol and by the Nova folding scheme.
Pallas and Vesta form a 2-cycle: the scalar field of one is the base
field of the other, which is what makes recursive folding possible.

## License

Apache License 2.0. See `LICENSE`.

## Company

QSOL LLC — Pocatello, Idaho — qsol.llc@gmail.com
