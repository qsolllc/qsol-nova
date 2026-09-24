use ff::{Field, PrimeField};
use pasta_curves::pallas;
use sha3::{Digest, Sha3_512};
use std::time::Instant;

type F = pallas::Scalar;

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

// R1CS: z = [x, w1, w2]. Constraint: w1 * w2 = x.
struct R1CS {
    a: Vec<F>,
    b: Vec<F>,
    c: Vec<F>,
}

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

fn fold(r: &R1CS, i1: &Rlx, i2: &Rlx, rho: F) -> (Rlx, F) {
    let (a1, b1, c1) = (r.az(&i1.z), r.bz(&i1.z), r.cz(&i1.z));
    let (a2, b2, c2) = (r.az(&i2.z), r.bz(&i2.z), r.cz(&i2.z));
    // Cross-term T
    let t = a1*b2 + a2*b1 - i1.u*c2 - i2.u*c1;
    let u = i1.u + rho * i2.u;
    let e = i1.e + rho * t + rho * rho * i2.e;
    let z: Vec<F> = i1.z.iter().zip(i2.z.iter())
        .map(|(a,b)| *a + rho * *b).collect();
    (Rlx { u, e, z }, t)
}

fn main() {
    println!("=== QSOL Nova-Style R1CS Fold on Pallas ===");
    println!();

    let t0 = Instant::now();
    let r = R1CS::new();

    // Two standard R1CS instances: u=1, E=0
    // Instance 1: 3 * 5 = 15
    // Instance 2: 7 * 11 = 77
    let i1 = Rlx { u: F::ONE, e: F::ZERO,
        z: vec![F::from(15u64), F::from(3u64),  F::from(5u64)] };
    let i2 = Rlx { u: F::ONE, e: F::ZERO,
        z: vec![F::from(77u64), F::from(7u64), F::from(11u64)] };

    println!("Instance 1: [x=15, w1=3,  w2=5 ]  satisfies = {}",
        satisfied(&r, i1.u, i1.e, &i1.z));
    println!("Instance 2: [x=77, w1=7,  w2=11]  satisfies = {}",
        satisfied(&r, i2.u, i2.e, &i2.z));
    println!();

    // Fiat-Shamir challenge over both instances
    let mut ch = Sha3_512::new();
    ch.update(b"QSOL_R1CS_FOLD_v1");
    for f in &i1.z { ch.update(f.to_repr()); }
    for f in &i2.z { ch.update(f.to_repr()); }
    let rho = h2s(&ch.finalize());
    println!("rho = {}", hex(&rho.to_repr()));
    println!();

    let (folded, t) = fold(&r, &i1, &i2, rho);
    println!("Cross-term T = {}", hex(&t.to_repr()));
    println!();
    println!("Folded u   = {}", hex(&folded.u.to_repr()));
    println!("Folded E   = {}", hex(&folded.e.to_repr()));
    println!("Folded z0  = {}", hex(&folded.z[0].to_repr()));
    println!("Folded z1  = {}", hex(&folded.z[1].to_repr()));
    println!("Folded z2  = {}", hex(&folded.z[2].to_repr()));
    println!();

    // Check: a·z ∘ b·z == u·c·z + E
    let lhs = r.az(&folded.z) * r.bz(&folded.z);
    let rhs = folded.u * r.cz(&folded.z) + folded.e;
    let fold_ok = lhs == rhs;
    println!("LHS (Az*Bz) = {}", hex(&lhs.to_repr()));
    println!("RHS (uCz+E) = {}", hex(&rhs.to_repr()));
    println!("FOLD_VALID  = {}", fold_ok);
    println!();

    // Tamper test 1: modify E by +1
    let tamper_e = !satisfied(&r, folded.u, folded.e + F::ONE, &folded.z);

    // Tamper test 2: modify z[0] (x) by +1
    let mut bad_z = folded.z.clone();
    bad_z[0] = bad_z[0] + F::ONE;
    let tamper_z = !satisfied(&r, folded.u, folded.e, &bad_z);

    println!("TAMPER_E_DETECTED = {}", tamper_e);
    println!("TAMPER_Z_DETECTED = {}", tamper_z);
    println!();

    let dt = t0.elapsed();
    println!("Fold time: {:?}", dt);

    let mut ev = Sha3_512::new();
    ev.update(b"QSOL_R1CS_FOLD_v1");
    ev.update(folded.u.to_repr());
    ev.update(folded.e.to_repr());
    for f in &folded.z { ev.update(f.to_repr()); }
    ev.update(if fold_ok          { &[1u8][..] } else { &[0u8][..] });
    ev.update(if tamper_e         { &[1u8][..] } else { &[0u8][..] });
    ev.update(if tamper_z         { &[1u8][..] } else { &[0u8][..] });
    let ev_hash = ev.finalize();
    println!("Evidence hash: {:x}", ev_hash);
    println!();

    let out = format!(
        "QSOL_R1CS_FOLD_v1\n\
         scheme = nova-style-relaxed-r1cs-fold-pallas\n\
         circuit = w1*w2 = x\n\
         fold_valid = {}\n\
         tamper_e_detected = {}\n\
         tamper_z_detected = {}\n\
         fold_time_us = {}\n\
         cross_term_t = {}\n\
         evidence_hash = {}\n",
        fold_ok, tamper_e, tamper_z, dt.as_micros(),
        hex(&t.to_repr()), hex(&ev_hash)
    );

    std::fs::write("quantfold_r1cs_proof.dat", &out).unwrap();
    let mut fh = Sha3_512::new();
    fh.update(out.as_bytes());
    let fhash = fh.finalize();
    std::fs::write("quantfold_r1cs_proof.dat.sig",
        format!("sha3-512:{}\n", hex(&fhash))).unwrap();

    println!("Written: quantfold_r1cs_proof.dat");
    println!("Written: quantfold_r1cs_proof.dat.sig");
    println!();
    println!("DONE — Nova-style relaxed R1CS fold with cross-term.");
}
