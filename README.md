# commit-groth09

A multiplicatively homomorphic commitment scheme, as described
in [Homomorphic Trapdoor Commitments to Group Elements](https://eprint.iacr.org/2009/007.pdf), implemented
using [BLS12-381](https://crates.io/crates/bls12_381).

## Basic usage

> Note: committing to bytes is not yet implemented!

```rust
fn commit_to_value() -> (Commitment, Randomness) {
    let commitment_key = CommitmentKey::<1>::generate();
    let value = Values::new([G2Affine::generator()]);
    let (commitment, randomness) = commitment_key.commit(&value);
}
```
