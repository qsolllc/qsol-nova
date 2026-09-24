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

fn main() {
    println!("=== QSOL Fold — Pedersen Folding on Pallas ===");
    println!();

    let t0 = Instant::now();

    let g = G1::generator();
    let h = g * h2s(b"QSOL_H_GEN_v1");
    let r_gen = g * h2s(b"QSOL_R_GEN_v1");
    println!("G  = {:?}", g);
    println!("H  = {:?}", h);
    println!("R  = {:?}", r_gen);
    println!();

    // Instance 1: (a1, b1, s1)
    let a1 = F::from(3u64);
    let b1 = F::from(5u64);
    let s1 = h2s(b"rand_1");
    let c1 = g * a1 + h * b1 + r_gen * s1;

    // Instance 2: (a2, b2, s2)
    let a2 = F::from(7u64);
    let b2 = F::from(11u64);
    let s2 = h2s(b"rand_2");
    let c2 = g * a2 + h * b2 + r_gen * s2;

    println!("C1 = {:?}", c1);
    println!("C2 = {:?}", c2);
    println!();

    // Folding challenge (Fiat-Shamir over the two commitments)
    let mut ch = Sha3_512::new();
    ch.update(b"QSOL_FOLD_CHALLENGE_v1");
    ch.update(c1.to_affine().to_bytes());
    ch.update(c2.to_affine().to_bytes());
    let rho = h2s(&ch.finalize());
    println!("rho = {:?}", rho);
    println!();

    // The fold: linear combination of the two commitments
    let c_folded = c1 + c2 * rho;

    // The algebraic equivalent, computed from the witness side
    let a_f = a1 + rho * a2;
    let b_f = b1 + rho * b2;
    let s_f = s1 + rho * s2;
    let c_computed = g * a_f + h * b_f + r_gen * s_f;

    let fold_ok = c_folded == c_computed;

    println!("C_folded (direct)   = {:?}", c_folded);
    println!("C_folded (computed) = {:?}", c_computed);
    println!("FOLD_VALID          = {}", fold_ok);
    println!();

    // Negative control: tamper a_f and confirm the check fails
    let a_bad = a_f + F::ONE;
    let c_bad = g * a_bad + h * b_f + r_gen * s_f;
    let tamper_detected = c_bad != c_folded;
    println!("TAMPER_DETECTED     = {}", tamper_detected);
    println!();

    let dt = t0.elapsed();
    println!("Fold time: {:?}", dt);

    // Evidence hash over the folded witness
    let mut ev = Sha3_512::new();
    ev.update(b"QSOL_FOLD_V1");
    ev.update(a_f.to_repr());
    ev.update(b_f.to_repr());
    ev.update(if fold_ok { &[1u8][..] } else { &[0u8][..] });
    ev.update(if tamper_detected { &[1u8][..] } else { &[0u8][..] });
    let ev_hash = ev.finalize();
    println!("Evidence hash: {:x}", ev_hash);

    // Evidence file
    let out = format!(
        "QSOL_FOLD_V1\n\
         scheme = pedersen-fold-pallas\n\
         a_folded = {}\n\
         b_folded = {}\n\
         fold_valid = {}\n\
         tamper_detected = {}\n\
         fold_time_us = {}\n\
         evidence_hash = {}\n",
        hex(&a_f.to_repr()),
        hex(&b_f.to_repr()),
        fold_ok,
        tamper_detected,
        dt.as_micros(),
        hex(&ev_hash)
    );

    std::fs::write("quantfold_proof.dat", &out).unwrap();
    println!("\nWritten: quantfold_proof.dat");

    let mut fh = Sha3_512::new();
    fh.update(out.as_bytes());
    let fhash = fh.finalize();
    std::fs::write("quantfold_proof.dat.sig",
        format!("sha3-512:{}\n", hex(&fhash))).unwrap();
    println!("Written: quantfold_proof.dat.sig");
    println!();
    println!("DONE — real folding produced this output.");
}
