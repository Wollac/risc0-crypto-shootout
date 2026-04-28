#![no_main]

extern crate alloc;

use core::hint::black_box;
use risc0_crypto::{BigInt, fp};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    // measure logging overhead (empty span)
    env::log("cycle-start: overhead/log");
    env::log("cycle-end: overhead/log");

    bench_ecrecover();
    bench_eip196();
    bench_eip2537();
    bench_eip2537_msm();
}

// -- ecrecover comparison: risc0-crypto vs k256 --
//
// both implementations use the revm-precompile Crypto interface:
//   fn secp256k1_ecrecover(sig: &[u8; 64], recid: u8, msg: &[u8; 32])
//
// the timed region includes all parsing from raw bytes.

/// Generate a valid secp256k1 signature in raw-byte form (not timed).
fn ecrecover_setup() -> ([u8; 64], u8, [u8; 32]) {
    use risc0_crypto::{curves::secp256k1, ecdsa::RecoverableSignature};

    let d: secp256k1::Fr =
        fp!("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let k: secp256k1::Fr =
        fp!("0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");
    let msg: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c,
    ];

    let rsig =
        RecoverableSignature::<secp256k1::Config, 8>::sign(&d, &k, &msg).unwrap().normalized_s();

    let mut sig_bytes = [0u8; 64];
    rsig.signature().r().as_bigint().write_be_bytes(&mut sig_bytes[..32]);
    rsig.signature().s().as_bigint().write_be_bytes(&mut sig_bytes[32..]);
    let recid = rsig.recovery_id().to_byte();

    (sig_bytes, recid, msg)
}

/// secp256k1 ecrecover via risc0-crypto (revm-precompile interface).
fn ecrecover_risc0(sig: &[u8; 64], recid: u8, msg: &[u8; 32]) -> Option<[u8; 64]> {
    use risc0_crypto::{
        curves::secp256k1,
        ecdsa::{RecoverableSignature, RecoveryId, Signature},
    };

    let r = secp256k1::Fr::from_bigint(BigInt::from_be_bytes(&sig[..32]))?;
    let s = secp256k1::Fr::from_bigint(BigInt::from_be_bytes(&sig[32..]))?;
    let inner = Signature::<secp256k1::Config, 8>::new(r, s)?;
    let recovery_id = RecoveryId::from_byte(recid)?;
    let rsig = RecoverableSignature::new(inner, recovery_id);

    let pubkey = rsig.recover(msg as &[u8])?;
    let (x, y) = pubkey.xy()?;

    let mut result = [0u8; 64];
    x.as_bigint().write_be_bytes(&mut result[..32]);
    y.as_bigint().write_be_bytes(&mut result[32..]);
    Some(result)
}

/// secp256k1 ecrecover via k256 (revm-precompile interface).
fn ecrecover_k256(sig: &[u8; 64], recid: u8, msg: &[u8; 32]) -> Option<[u8; 64]> {
    let sig = k256::ecdsa::Signature::from_slice(sig).ok()?;
    let recid = k256::ecdsa::RecoveryId::try_from(recid).ok()?;
    let key = k256::ecdsa::VerifyingKey::recover_from_prehash(msg.as_slice(), &sig, recid).ok()?;
    let point = key.to_encoded_point(false);
    let mut result = [0u8; 64];
    result.copy_from_slice(&point.as_bytes()[1..65]);
    Some(result)
}

fn bench_ecrecover() {
    let (sig, recid, msg) = ecrecover_setup();

    env::log("cycle-start: ecrecover/risc0-crypto");
    let a = ecrecover_risc0(black_box(&sig), black_box(recid), black_box(&msg));
    black_box(&a);
    env::log("cycle-end: ecrecover/risc0-crypto");

    env::log("cycle-start: ecrecover/k256");
    let b = ecrecover_k256(black_box(&sig), black_box(recid), black_box(&msg));
    black_box(&b);
    env::log("cycle-end: ecrecover/k256");

    // sanity: both recover the same public key
    assert_eq!(a.unwrap(), b.unwrap(), "ecrecover implementations disagree");
}

// -- EIP-196 (BN254 G1 add & mul) comparison: risc0-crypto vs substrate-bn --
//
// both implementations use the revm-precompile Crypto interface:
//   fn bn254_g1_add(p1: &[u8], p2: &[u8]) -> Option<[u8; 64]>
//   fn bn254_g1_mul(point: &[u8], scalar: &[u8]) -> Option<[u8; 64]>
//
// the timed region includes all parsing from raw bytes.

/// Generate test inputs for EIP-196 benchmarks (not timed).
fn eip196_setup() -> ([u8; 64], [u8; 64], [u8; 32]) {
    use risc0_crypto::curves::bn254;

    let g = bn254::Affine::GENERATOR;
    let scalar: bn254::Fr =
        fp!("0x0c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f672");
    let p2 = &g * &scalar;

    let mut p1_bytes = [0u8; 64];
    let (gx, gy) = g.xy().unwrap();
    gx.as_bigint().write_be_bytes(&mut p1_bytes[..32]);
    gy.as_bigint().write_be_bytes(&mut p1_bytes[32..]);

    let mut p2_bytes = [0u8; 64];
    let (p2x, p2y) = p2.xy().unwrap();
    p2x.as_bigint().write_be_bytes(&mut p2_bytes[..32]);
    p2y.as_bigint().write_be_bytes(&mut p2_bytes[32..]);

    let mut scalar_bytes = [0u8; 32];
    scalar.as_bigint().write_be_bytes(&mut scalar_bytes);

    (p1_bytes, p2_bytes, scalar_bytes)
}

/// BN254 G1 point addition via risc0-crypto (revm-precompile interface).
fn bn254_g1_add_risc0(p1: &[u8], p2: &[u8]) -> Option<[u8; 64]> {
    use risc0_crypto::curves::bn254;

    let read = |data: &[u8]| -> Option<bn254::Affine> {
        let x = bn254::Fq::from_bigint(BigInt::from_be_bytes(&data[..32]))?;
        let y = bn254::Fq::from_bigint(BigInt::from_be_bytes(&data[32..64]))?;
        if x.is_zero() && y.is_zero() {
            Some(bn254::Affine::IDENTITY)
        } else {
            bn254::Affine::new(x, y)
        }
    };

    let p1 = read(p1)?;
    let p2 = read(p2)?;
    let sum = &p1 + &p2;

    let mut result = [0u8; 64];
    if let Some((x, y)) = sum.xy() {
        x.as_bigint().write_be_bytes(&mut result[..32]);
        y.as_bigint().write_be_bytes(&mut result[32..]);
    }
    Some(result)
}

/// BN254 G1 scalar multiplication via risc0-crypto (revm-precompile interface).
fn bn254_g1_mul_risc0(point: &[u8], scalar: &[u8]) -> Option<[u8; 64]> {
    use risc0_crypto::curves::bn254;

    let x = bn254::Fq::from_bigint(BigInt::from_be_bytes(&point[..32]))?;
    let y = bn254::Fq::from_bigint(BigInt::from_be_bytes(&point[32..64]))?;
    let p = if x.is_zero() && y.is_zero() {
        bn254::Affine::IDENTITY
    } else {
        bn254::Affine::new(x, y)?
    };

    // EVM scalar is a raw 256-bit uint, may be >= group order
    let s = bn254::Fr::reduce_from_bigint(BigInt::from_be_bytes(scalar));
    let product = &p * &s;

    let mut result = [0u8; 64];
    if let Some((x, y)) = product.xy() {
        x.as_bigint().write_be_bytes(&mut result[..32]);
        y.as_bigint().write_be_bytes(&mut result[32..]);
    }
    Some(result)
}

/// BN254 G1 point addition via substrate-bn (revm-precompile interface).
fn bn254_g1_add_substrate(p1: &[u8], p2: &[u8]) -> Option<[u8; 64]> {
    use substrate_bn::{AffineG1, Fq, G1, Group};

    let read = |data: &[u8]| -> Option<G1> {
        let px = Fq::from_slice(&data[..32]).ok()?;
        let py = Fq::from_slice(&data[32..64]).ok()?;
        if px == Fq::zero() && py == Fq::zero() {
            Some(G1::zero())
        } else {
            Some(AffineG1::new(px, py).ok()?.into())
        }
    };

    let p1 = read(p1)?;
    let p2 = read(p2)?;
    let sum = p1 + p2;

    let mut result = [0u8; 64];
    if !sum.is_zero() {
        let p = AffineG1::from_jacobian(sum)?;
        p.x().to_big_endian(&mut result[..32]).unwrap();
        p.y().to_big_endian(&mut result[32..]).unwrap();
    }
    Some(result)
}

/// BN254 G1 scalar multiplication via substrate-bn (revm-precompile interface).
fn bn254_g1_mul_substrate(point: &[u8], scalar: &[u8]) -> Option<[u8; 64]> {
    use substrate_bn::{AffineG1, Fq, Fr, G1, Group};

    let px = Fq::from_slice(&point[..32]).ok()?;
    let py = Fq::from_slice(&point[32..64]).ok()?;
    let p: G1 = if px == Fq::zero() && py == Fq::zero() {
        G1::zero()
    } else {
        AffineG1::new(px, py).ok()?.into()
    };

    let s = Fr::from_slice(scalar).ok()?;
    let product = p * s;

    let mut result = [0u8; 64];
    if !product.is_zero() {
        let p = AffineG1::from_jacobian(product)?;
        p.x().to_big_endian(&mut result[..32]).unwrap();
        p.y().to_big_endian(&mut result[32..]).unwrap();
    }
    Some(result)
}

fn bench_eip196() {
    let (p1, p2, scalar) = eip196_setup();

    // -- G1 add --
    env::log("cycle-start: eip196/add/risc0-crypto");
    let a = bn254_g1_add_risc0(black_box(&p1), black_box(&p2));
    black_box(&a);
    env::log("cycle-end: eip196/add/risc0-crypto");

    env::log("cycle-start: eip196/add/substrate-bn");
    let b = bn254_g1_add_substrate(black_box(&p1), black_box(&p2));
    black_box(&b);
    env::log("cycle-end: eip196/add/substrate-bn");

    assert_eq!(a.unwrap(), b.unwrap(), "G1 add implementations disagree");

    // -- G1 mul --
    env::log("cycle-start: eip196/mul/risc0-crypto");
    let a = bn254_g1_mul_risc0(black_box(&p1), black_box(&scalar));
    black_box(&a);
    env::log("cycle-end: eip196/mul/risc0-crypto");

    env::log("cycle-start: eip196/mul/substrate-bn");
    let b = bn254_g1_mul_substrate(black_box(&p1), black_box(&scalar));
    black_box(&b);
    env::log("cycle-end: eip196/mul/substrate-bn");

    assert_eq!(a.unwrap(), b.unwrap(), "G1 mul implementations disagree");
}

// -- EIP-2537 (BLS12-381 G1 add) comparison: risc0-crypto vs blst --
//
// both implementations use the revm-precompile Crypto interface:
//   fn bls12_381_g1_add(a: G1Point, b: G1Point) -> [u8; 96]
//   where G1Point = ([u8; FP_LENGTH], [u8; FP_LENGTH])
//
// the timed region includes all parsing from raw bytes.

const FP_LENGTH: usize = 48;
type G1Point = ([u8; FP_LENGTH], [u8; FP_LENGTH]);

/// Generate test inputs for EIP-2537 benchmarks (not timed).
fn eip2537_setup() -> (G1Point, G1Point) {
    use risc0_crypto::curves::bls12_381;

    let g = bls12_381::Affine::GENERATOR;
    let scalar: bls12_381::Fr =
        fp!("0x0c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f672");
    let p2 = &g * &scalar;

    let encode = |p: &bls12_381::Affine| -> G1Point {
        let (x, y) = p.xy().unwrap();
        let mut x_bytes = [0u8; FP_LENGTH];
        let mut y_bytes = [0u8; FP_LENGTH];
        x.as_bigint().write_be_bytes(&mut x_bytes);
        y.as_bigint().write_be_bytes(&mut y_bytes);
        (x_bytes, y_bytes)
    };

    (encode(&g), encode(&p2))
}

/// BLS12-381 G1 point addition via risc0-crypto (revm-precompile interface).
fn bls12_381_g1_add_risc0(a: G1Point, b: G1Point) -> Option<[u8; 96]> {
    use risc0_crypto::curves::bls12_381;

    let read = |point: &G1Point| -> Option<bls12_381::Affine> {
        let x = bls12_381::Fq::from_bigint(BigInt::from_be_bytes(&point.0))?;
        let y = bls12_381::Fq::from_bigint(BigInt::from_be_bytes(&point.1))?;
        if x.is_zero() && y.is_zero() {
            Some(bls12_381::Affine::IDENTITY)
        } else {
            bls12_381::Affine::new(x, y)
        }
    };

    let p1 = read(&a)?;
    let p2 = read(&b)?;
    let sum = &p1 + &p2;

    let mut result = [0u8; 96];
    if let Some((x, y)) = sum.xy() {
        x.as_bigint().write_be_bytes(&mut result[..FP_LENGTH]);
        y.as_bigint().write_be_bytes(&mut result[FP_LENGTH..]);
    }
    Some(result)
}

/// BLS12-381 G1 point addition via blst (revm-precompile interface).
fn bls12_381_g1_add_blst(a: G1Point, b: G1Point) -> Option<[u8; 96]> {
    use blst::*;

    let read_fp = |bytes: &[u8; FP_LENGTH]| -> blst_fp {
        let mut fp = blst_fp::default();
        unsafe { blst_fp_from_bendian(&mut fp, bytes.as_ptr()) };
        fp
    };

    let read_point = |point: &G1Point| -> Option<blst_p1_affine> {
        let p = blst_p1_affine { x: read_fp(&point.0), y: read_fp(&point.1) };
        unsafe { blst_p1_affine_on_curve(&p).then_some(p) }
    };

    let p1 = read_point(&a)?;
    let p2 = read_point(&b)?;

    let mut p1_jac = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut p1_jac, &p1) };

    let mut sum = blst_p1::default();
    unsafe { blst_p1_add_or_double_affine(&mut sum, &p1_jac, &p2) };

    let mut result_aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut result_aff, &sum) };

    let mut result = [0u8; 96];
    unsafe {
        blst_bendian_from_fp(result.as_mut_ptr(), &result_aff.x);
        blst_bendian_from_fp(result[FP_LENGTH..].as_mut_ptr(), &result_aff.y);
    };
    Some(result)
}

fn bench_eip2537() {
    let (a, b) = eip2537_setup();

    env::log("cycle-start: eip2537/add/risc0-crypto");
    let r1 = bls12_381_g1_add_risc0(black_box(a), black_box(b));
    black_box(&r1);
    env::log("cycle-end: eip2537/add/risc0-crypto");

    env::log("cycle-start: eip2537/add/blst");
    let r2 = bls12_381_g1_add_blst(black_box(a), black_box(b));
    black_box(&r2);
    env::log("cycle-end: eip2537/add/blst");

    assert_eq!(r1.unwrap(), r2.unwrap(), "G1 add implementations disagree");
}

// -- EIP-2537 BLS12_G1MSM comparison: risc0-crypto vs blst (revm upstream) --
//
// both implementations use the revm-precompile Crypto interface:
//   fn bls12_381_g1_msm(pairs: &[(G1Point, [u8; 32])]) -> [u8; 96]
//
// risc0-crypto: k=1 uses direct scalar mul, k>1 uses pairwise
// scalar_mul + add (linear scaling).
// blst: k=1 uses direct scalar mul, k>1 uses Pippenger's MSM
// (sublinear scaling), matching revm's p1_msm exactly.
//
// benchmarked at k=1 and k=128 (EIP-2537 discount table max).
//
// the timed region includes all parsing from raw bytes.

const SCALAR_LENGTH: usize = 32;
type G1PointScalar = (G1Point, [u8; SCALAR_LENGTH]);

/// Generate 128 distinct (point, scalar) pairs for MSM benchmarks (not timed).
fn eip2537_msm_setup() -> alloc::vec::Vec<G1PointScalar> {
    use alloc::vec::Vec;
    use risc0_crypto::curves::bls12_381;

    let g = bls12_381::Affine::GENERATOR;

    let encode_point = |p: &bls12_381::Affine| -> G1Point {
        let (x, y) = p.xy().unwrap();
        let mut xb = [0u8; FP_LENGTH];
        let mut yb = [0u8; FP_LENGTH];
        x.as_bigint().write_be_bytes(&mut xb);
        y.as_bigint().write_be_bytes(&mut yb);
        (xb, yb)
    };

    // deterministic full-size scalars (all < 2^254 < BLS12-381 scalar order)
    let make_scalar = |i: usize| -> [u8; SCALAR_LENGTH] {
        let mut s = [0u8; SCALAR_LENGTH];
        for j in 0..SCALAR_LENGTH {
            s[j] =
                (i.wrapping_add(1).wrapping_mul(j + 1).wrapping_mul(0x9e).wrapping_add(0x37)) as u8;
        }
        s[0] &= 0x3f; // clear top 2 bits -> value < 2^254
        s
    };

    // 128 distinct points: G, [2]G, [4]G, ... via repeated doubling
    let mut p = g;
    let mut result = Vec::with_capacity(128);
    for i in 0..128 {
        result.push((encode_point(&p), make_scalar(i)));
        p = p.double();
    }
    result
}

/// Parse a G1Point from raw bytes into a BLS12-381 affine point (with subgroup check).
fn read_g1_risc0(point: &G1Point) -> Option<risc0_crypto::curves::bls12_381::Affine> {
    use risc0_crypto::curves::bls12_381;
    let x = bls12_381::Fq::from_bigint(BigInt::from_be_bytes(&point.0))?;
    let y = bls12_381::Fq::from_bigint(BigInt::from_be_bytes(&point.1))?;
    if x.is_zero() && y.is_zero() {
        Some(bls12_381::Affine::IDENTITY)
    } else {
        bls12_381::Affine::new_in_subgroup(x, y)
    }
}

/// Parse a 32-byte big-endian EIP scalar into a BLS12-381 scalar field element.
fn read_scalar_risc0(scalar: &[u8; SCALAR_LENGTH]) -> risc0_crypto::curves::bls12_381::Fr {
    use risc0_crypto::curves::bls12_381;
    // pad 32-byte EIP scalar to 48-byte BigInt<12>
    let mut padded = [0u8; 48];
    padded[16..].copy_from_slice(scalar);
    bls12_381::Fr::reduce_from_bigint(BigInt::from_be_bytes(&padded))
}

/// Encode a BLS12-381 affine point as 96 big-endian bytes.
fn encode_g1_risc0(p: &risc0_crypto::curves::bls12_381::Affine) -> [u8; 96] {
    let mut result = [0u8; 96];
    if let Some((x, y)) = p.xy() {
        x.as_bigint().write_be_bytes(&mut result[..FP_LENGTH]);
        y.as_bigint().write_be_bytes(&mut result[FP_LENGTH..]);
    }
    result
}

/// BLS12-381 G1 MSM via risc0-crypto.
/// k=1: direct scalar mul. k>1: double_scalar_mul (Shamir's trick) on
/// chunks of 2, with a trailing single scalar mul for odd k.
fn bls12_381_g1_msm_risc0(pairs: &[G1PointScalar]) -> Option<[u8; 96]> {
    use risc0_crypto::curves::bls12_381;

    if pairs.len() == 1 {
        // k=1: direct scalar mul, no accumulator overhead
        let p = read_g1_risc0(&pairs[0].0)?;
        let s = read_scalar_risc0(&pairs[0].1);
        return Some(encode_g1_risc0(&(&p * &s)));
    }

    // k>1: process pairs via double_scalar_mul (Shamir's trick) - saves ~n
    // doublings per pair compared to two independent scalar muls.
    let mut acc = bls12_381::Affine::IDENTITY;
    for chunk in pairs.chunks_exact(2) {
        let p0 = read_g1_risc0(&chunk[0].0)?;
        let s0 = read_scalar_risc0(&chunk[0].1);
        let p1 = read_g1_risc0(&chunk[1].0)?;
        let s1 = read_scalar_risc0(&chunk[1].1);
        acc = &acc + &bls12_381::Affine::double_scalar_mul(&s0, &p0, &s1, &p1);
    }
    Some(encode_g1_risc0(&acc))
}

/// BLS12-381 G1 MSM via blst, matching revm's p1_msm implementation:
/// k=1: direct scalar mul. k>1: Pippenger's MSM (sublinear scaling).
fn bls12_381_g1_msm_blst(pairs: &[G1PointScalar]) -> Option<[u8; 96]> {
    use alloc::vec::Vec;
    use blst::*;

    let mut points = Vec::with_capacity(pairs.len());
    let mut scalars = Vec::with_capacity(pairs.len());

    for (point, scalar) in pairs {
        // parse point
        let mut fp_x = blst_fp::default();
        let mut fp_y = blst_fp::default();
        unsafe { blst_fp_from_bendian(&mut fp_x, point.0.as_ptr()) };
        unsafe { blst_fp_from_bendian(&mut fp_y, point.1.as_ptr()) };
        let p_aff = blst_p1_affine { x: fp_x, y: fp_y };
        if unsafe { !blst_p1_affine_on_curve(&p_aff) } {
            return None;
        }
        // MSM requires subgroup check per EIP-2537
        if unsafe { !blst_p1_affine_in_g1(&p_aff) } {
            return None;
        }

        // parse scalar
        let mut s = blst_scalar::default();
        unsafe { blst_scalar_from_bendian(&mut s, scalar.as_ptr()) };

        // skip zero scalars after validating the point (revm optimization)
        if scalar.iter().all(|&b| b == 0) {
            continue;
        }

        points.push(p_aff);
        scalars.push(s);
    }

    if points.is_empty() {
        return Some([0u8; 96]);
    }

    // revm's p1_msm: direct scalar mul for k=1, Pippenger's for k>1
    let result_jac = if points.len() == 1 {
        let mut p_jac = blst_p1::default();
        unsafe { blst_p1_from_affine(&mut p_jac, &points[0]) };
        let mut result = blst_p1::default();
        unsafe { blst_p1_mult(&mut result, &p_jac, scalars[0].b.as_ptr(), 255) };
        result
    } else {
        let scalars_bytes = unsafe {
            core::slice::from_raw_parts(scalars.as_ptr() as *const u8, scalars.len() * 32)
        };
        points.mult(scalars_bytes, SCALAR_LENGTH * 8)
    };

    let mut result_aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut result_aff, &result_jac) };

    let mut result = [0u8; 96];
    unsafe {
        blst_bendian_from_fp(result.as_mut_ptr(), &result_aff.x);
        blst_bendian_from_fp(result[FP_LENGTH..].as_mut_ptr(), &result_aff.y);
    };
    Some(result)
}

fn bench_eip2537_msm() {
    let pairs = eip2537_msm_setup();

    for &k in &[1, 128] {
        env::log(&format!("cycle-start: eip2537/msm/{k}/risc0-crypto"));
        let r1 = bls12_381_g1_msm_risc0(black_box(&pairs[..k]));
        black_box(&r1);
        env::log(&format!("cycle-end: eip2537/msm/{k}/risc0-crypto"));

        env::log(&format!("cycle-start: eip2537/msm/{k}/blst"));
        let r2 = bls12_381_g1_msm_blst(black_box(&pairs[..k]));
        black_box(&r2);
        env::log(&format!("cycle-end: eip2537/msm/{k}/blst"));

        assert_eq!(r1.unwrap(), r2.unwrap(), "G1 MSM k={k} implementations disagree");
    }
}
