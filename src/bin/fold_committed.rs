use ff::{Field, PrimeField};
use group::{Curve, Group, GroupEncoding};
use pasta_curves::pallas;
use sha3::{Digest, Sha3_512};
use std::time::Instant;

type F = pallas::Scalar;
type G1 = pallas::Point;

fn h2s(label: &[u8]) -> F {
    let mut h = Sha3_512::new();
    h.update(label);
    let d = h.finalize();
    let mut s = F::ZERO;
    let mut p = F::ONE;
    let shift = F::from(u64::MAX) + F::ONE;
    for i in 0..4 {
        let v = u64::from_le_bytes(d[i*8..(i+1)*8].try_into().unwrap());
        s += F::from(v) * p;
        p *= shift;
    }
    s
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// Pedersen commitment: C = value * G + r * H
fn commit(g: G1, h: G1, value: F, r: F) -> G1 {
    g * value + h * r
}

fn commit_bytes(p: G1) -> [u8; 32] {
    p.to_affine().to_bytes()
}

// Fiat-Shamir over a list of points
fn fs(label: &[u8], points: &[G1]) -> F {
    let mut ch = Sha3_512::new();
    ch.update(label);
    for p in points {
        ch.update(commit_bytes(*p));
    }
    h2s(&ch.finalize())
}

// R1CS: z = [x, w1, w2], constraint w1 * w2 = x
struct R1CS { a: Vec<F>, b: Vec<F>, c: Vec<F> }

impl R1CS {
    fn new() -> Self {
        R1CS {
            a: vec![F::ZERO, F::ONE,  F::ZERO],
            b: vec![F::ZERO, F::ZERO, F::ONE ],
            c: vec![F::ONE,  F::ZERO, F::ZERO],
        }
    }
    fn dot(v: &[F], z: &[F]) -> F {
        v.iter().zip(z.iter()).map(|(a,b)| *a * *b).fold(F::ZERO, |s,x| s+x)
    }
    fn az(&self, z: &[F]) -> F { Self::dot(&self.a, z) }
    fn bz(&self, z: &[F]) -> F { Self::dot(&self.b, z) }
    fn cz(&self, z: &[F]) -> F { Self::dot(&self.c, z) }
}

#[derive(Clone)]
struct Rlx { u: F, e: F, z: Vec<F> }

fn satisfied(r: &R1CS, u: F, e: F, z: &[F]) -> bool {
    r.az(z) * r.bz(z) == u * r.cz(z) + e
}

fn main() {
    println!("=== QSOL Committed Nova Fold on Pallas ===");
    println!("(Verifier never sees z, E, or the folded witness)");
    println!();

    let t0 = Instant::now();
    let r = R1CS::new();

    // Generators
    let g = G1::generator();
    let h = g * h2s(b"QSOL_BLIND_GEN_v1");

    // Two satisfying instances, each with randomness
    let z1 = vec![F::from(15u64), F::from(3u64), F::from(5u64)];
    let z2 = vec![F::from(77u64), F::from(7u64), F::from(11u64)];
    let r1: Vec<F> = (0..3).map(|i| h2s(format!("r1_{}", i).as_bytes())).collect();
    let r2: Vec<F> = (0..3).map(|i| h2s(format!("r2_{}", i).as_bytes())).collect();

    // Commit to witness vectors component-wise
    let c1: Vec<G1> = (0..3).map(|i| commit(g, h, z1[i], r1[i])).collect();
    let c2: Vec<G1> = (0..3).map(|i| commit(g, h, z2[i], r2[i])).collect();

    println!("Instance 1 satisfies: {}", satisfied(&r, F::ONE, F::ZERO, &z1));
    println!("Instance 2 satisfies: {}", satisfied(&r, F::ONE, F::ZERO, &z2));
    println!();

    // Fiat-Shamir over the six commitments — verifier's challenge
    let mut all = Vec::new();
    all.extend(c1.iter());
    all.extend(c2.iter());
    let rho = fs(b"QSOL_COMMITTED_FOLD_v1", &all);
    println!("rho (from commitments) = {}", hex(&rho.to_repr()));
    println!();

    // Prover folds the witness and randomness
    let z_f: Vec<F> = (0..3).map(|i| z1[i] + rho * z2[i]).collect();
    let r_f: Vec<F> = (0..3).map(|i| r1[i] + rho * r2[i]).collect();

    // Prover commits to the folded witness
    let c_f: Vec<G1> = (0..3).map(|i| commit(g, h, z_f[i], r_f[i])).collect();

    // Verifier's side: homomorphic fold of the input commitments
    let c_expected: Vec<G1> = (0..3).map(|i| c1[i] + c2[i] * rho).collect();

    // Compare
    let mut fold_ok = true;
    for i in 0..3 {
        if c_f[i] != c_expected[i] { fold_ok = false; }
    }

    println!("Verifier-side fold (homomorphic):");
    for i in 0..3 {
        println!("  C[{}]_folded  = {}", i, hex(&commit_bytes(c_f[i])));
    }
    println!();

    println!("FOLD_VALID = {}", fold_ok);
    println!();

    // Tamper: change one input commitment, verify fold mismatches
    let mut c1_bad = c1.clone();
    c1_bad[0] = c1_bad[0] + g;
    let c_bad: Vec<G1> = (0..3).map(|i| c1_bad[i] + c2[i] * rho).collect();
    let tamper_detected = c_bad[0] != c_f[0];
    println!("TAMPER_DETECTED = {}", tamper_detected);
    println!();

    // Verify the folded instance satisfies relaxed R1CS (prover-side check)
    let (a, b, c) = (r.az(&z_f), r.bz(&z_f), r.cz(&z_f));
    let t = r.az(&z1)*r.bz(&z2) + r.az(&z2)*r.bz(&z1) - F::ONE*r.cz(&z2) - F::ONE*r.cz(&z1);
    let u_f = F::ONE + rho * F::ONE;
    let e_f = F::ZERO + rho * t + rho*rho * F::ZERO;
    let rlx_ok = a * b == u_f * c + e_f;
    println!("Folded R1CS satisfied (prover check) = {}", rlx_ok);
    println!();

    let dt = t0.elapsed();
    println!("Fold time: {:?}", dt);

    let mut ev = Sha3_512::new();
    ev.update(b"QSOL_COMMITTED_FOLD_v1");
    ev.update(rho.to_repr());
    for i in 0..3 { ev.update(commit_bytes(c_f[i])); }
    ev.update(if fold_ok         { &[1u8][..] } else { &[0u8][..] });
    ev.update(if tamper_detected { &[1u8][..] } else { &[0u8][..] });
    ev.update(if rlx_ok          { &[1u8][..] } else { &[0u8][..] });
    let ev_hash = ev.finalize();
    println!("Evidence hash: {:x}", ev_hash);
    println!();

    let out = format!(
        "QSOL_COMMITTED_FOLD_v1\n\
         scheme = committed-nova-fold-pallas\n\
         circuit = w1*w2 = x\n\
         verifier_sees_witness = false\n\
         rho = {}\n\
         fold_valid = {}\n\
         tamper_detected = {}\n\
         folded_r1cs_satisfied = {}\n\
         fold_time_us = {}\n\
         evidence_hash = {}\n",
        hex(&rho.to_repr()),
        fold_ok, tamper_detected, rlx_ok, dt.as_micros(),
        hex(&ev_hash)
    );

    std::fs::write("quantfold_committed_proof.dat", &out).unwrap();
    let mut fh = Sha3_512::new();
    fh.update(out.as_bytes());
    let fhash = fh.finalize();
    std::fs::write("quantfold_committed_proof.dat.sig",
        format!("sha3-512:{}\n", hex(&fhash))).unwrap();

    println!("Written: quantfold_committed_proof.dat");
    println!("Written: quantfold_committed_proof.dat.sig");
    println!();
    println!("DONE — verifier folded commitments, never saw z.");
}
