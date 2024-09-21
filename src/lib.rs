//! [Homomorphic Trapdoor Commitments to Group Elements](https://eprint.iacr.org/2009/007.pdf) as
//! described by Jens Groth.
//!
//! This implementation uses [BLS12-381](https://docs.rs/bls12_381) for the groups and pairing.

use bls12_381::{pairing, G1Affine, G2Affine, Gt, Scalar};
use ff::Field;
use rand::prelude::*;

pub struct GrothCommitment {}

type Value<const N: usize> = [G2Affine; N];
pub struct Randomness {
    r: G2Affine,
    s: G2Affine,
}
type Commitment = [Gt; 2];

pub struct PublicParameters<const N: usize> {
    g_arr: [G1Affine; N],
    h_arr: [G1Affine; N],
    gr: G1Affine,
    hr: G1Affine,
    gs: G1Affine,
    hs: G1Affine,
}

impl GrothCommitment {
    pub fn generate_public_parameters<const N: usize>() -> PublicParameters<N> {
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

        PublicParameters {
            g_arr,
            h_arr,
            gr,
            hr,
            gs,
            hs,
        }
    }

    pub fn check_public_parameters<const N: usize>(pp: &PublicParameters<N>) -> bool {
        todo!()
    }

    fn commit_with_randomness<const N: usize>(
        pp: &PublicParameters<N>,
        value: &Value<N>,
        randomness: &Randomness,
    ) -> Commitment {
        let mut c = pairing(&pp.gr, &randomness.r) + pairing(&pp.gs, &randomness.s);
        for i in 0..N {
            c += pairing(&pp.g_arr[i], &value[i])
        }

        let mut d = pairing(&pp.hr, &randomness.r) + pairing(&pp.hs, &randomness.s);
        for i in 0..N {
            d += pairing(&pp.h_arr[i], &value[i])
        }

        [c, d]
    }

    fn commit<const N: usize>(
        pp: &PublicParameters<N>,
        value: &Value<N>,
    ) -> (Commitment, Randomness) {
        let mut rng = thread_rng();
        let g = G2Affine::generator();
        let r = gen_g2_elem(&mut rng, g);
        let s = gen_g2_elem(&mut rng, g);
        let randomness = [r, s];

        let commitment = Self::commit_with_randomness(pp, value, &randomness);

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
    fn accept_honest_parameters() {
        let pp = GrothCommitment::generate_public_parameters::<10>();
        assert!(GrothCommitment::check_public_parameters::<10>(&pp));
    }

    #[test]
    fn it_works() {
        let pp = GrothCommitment::generate_public_parameters::<10>();
        let value = [G2Affine::generator(); 10];
        let (c, r) = GrothCommitment::commit(&pp, &value);
        let d = GrothCommitment::commit_with_randomness(&pp, &value, &r);
        assert_eq!(c, d);
    }
}
