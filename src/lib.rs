//! [Homomorphic Trapdoor Commitments to Group Elements](https://eprint.iacr.org/2009/007.pdf) as
//! described by Jens Groth.
//!
//! This implementation uses [BLS12-381](https://docs.rs/bls12_381) for the groups and pairing.

use bls12_381::{pairing, G1Affine, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use group::Group;
use rand::prelude::*;
use std::iter::zip;
use std::ops::{Add, Mul};

pub struct Values<const N: usize> {
    values: [G2Affine; N],
}

impl<const N: usize> Values<N> {
    pub fn new(values: [G2Affine; N]) -> Self {
        Values { values }
    }

    pub(crate) fn random() -> Self {
        let mut values = Vec::with_capacity(N);
        for _ in 0..N {
            values.push(G2Affine::from(G2Projective::random(thread_rng())));
        }
        Values {
            values: values.try_into().unwrap(),
        }
    }

    pub fn from_bytes(_bytes: &[u8]) -> Self {
        todo!("implement converting to and from bytes")
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        todo!("implement converting to and from bytes")
    }
}

impl<const N: usize> Mul for &Values<N> {
    type Output = Values<N>;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut values = Vec::with_capacity(N);
        for i in 0..N {
            let v = G2Affine::from(self.values[i] + &rhs.values[i].into());
            values.push(v);
        }
        Values {
            values: values.try_into().unwrap(),
        }
    }
}

pub struct Randomness {
    r: G2Affine,
    s: G2Affine,
}

impl Randomness {
    pub fn gen(rng: &mut impl RngCore) -> Self {
        let g = G2Affine::generator();
        let r = gen_g2_elem(rng, g);
        let s = gen_g2_elem(rng, g);
        Randomness { r, s }
    }
}

impl Mul for &Randomness {
    type Output = Randomness;

    fn mul(self, rhs: Self) -> Self::Output {
        let r = self.r.add(&G2Projective::from(rhs.r)).into();
        let s = self.s.add(&G2Projective::from(rhs.s)).into();
        Randomness { r, s }
    }
}

#[derive(Debug, PartialEq)]
pub struct Commitment {
    c: Gt,
    d: Gt,
}

impl Mul for &Commitment {
    type Output = Commitment;

    fn mul(self, rhs: &Commitment) -> Self::Output {
        let c = self.c.add(rhs.c);
        let d = self.d.add(rhs.d);
        Commitment { c, d }
    }
}

pub struct CommitmentKey<const N: usize> {
    g_arr: [G1Affine; N],
    h_arr: [G1Affine; N],
    gr: G1Affine,
    hr: G1Affine,
    gs: G1Affine,
    hs: G1Affine,
}

impl<const N: usize> CommitmentKey<N> {
    pub fn generate() -> CommitmentKey<N> {
        let mut rng = thread_rng();
        let g = G1Affine::generator();

        let mut g_vec = Vec::with_capacity(N);
        let mut h_vec = Vec::with_capacity(N);
        for _ in 0..N {
            g_vec.push(gen_g1_elem(&mut rng, g));
            h_vec.push(gen_g1_elem(&mut rng, g));
        }
        let g_arr = g_vec.try_into().unwrap();
        let h_arr = h_vec.try_into().unwrap();

        let gr = gen_g1_elem(&mut rng, g);
        let hr = gen_g1_elem(&mut rng, g);

        let gs = gen_g1_elem(&mut rng, g);
        let hs = gen_g1_elem(&mut rng, g);

        CommitmentKey {
            g_arr,
            h_arr,
            gr,
            hr,
            gs,
            hs,
        }
    }

    pub fn commit_with_randomness(&self, value: &Values<N>, randomness: &Randomness) -> Commitment {
        let mut c = pairing(&self.gr, &randomness.r) + pairing(&self.gs, &randomness.s);
        for (g, v) in zip(&self.g_arr, &value.values) {
            c += pairing(g, v)
        }

        let mut d = pairing(&self.hr, &randomness.r) + pairing(&self.hs, &randomness.s);
        for (h, v) in zip(&self.h_arr, &value.values) {
            d += pairing(h, v)
        }

        Commitment { c, d }
    }

    pub fn commit(&self, value: &Values<N>) -> (Commitment, Randomness) {
        let randomness = Randomness::gen(&mut thread_rng());
        let commitment = Self::commit_with_randomness(self, value, &randomness);
        (commitment, randomness)
    }
}

fn gen_g1_elem(rng: &mut impl RngCore, generator: G1Affine) -> G1Affine {
    let r = Scalar::random(rng);
    (generator * r).into()
}

fn gen_g2_elem(rng: &mut impl RngCore, generator: G2Affine) -> G2Affine {
    let r = Scalar::random(rng);
    (generator * r).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let ck = CommitmentKey::<10>::generate();
        let value = Values::random();
        let (c, r) = ck.commit(&value);
        let d = ck.commit_with_randomness(&value, &r);
        assert_eq!(c, d);
    }

    #[test]
    fn multiplicatively_homomorphic() {
        let ck = CommitmentKey::<1>::generate();

        let v1 = Values::random();
        let (c1, r1) = ck.commit(&v1);

        let v2 = Values::random();
        let (c2, r2) = ck.commit(&v2);

        let v_mul = &v1 * &v2;
        let r_mul = &r1 * &r2;
        let expected = ck.commit_with_randomness(&v_mul, &r_mul);

        let actual = c1.mul(&c2);

        assert_eq!(actual, expected);
    }
}
