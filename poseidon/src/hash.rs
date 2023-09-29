use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use liminal_ark_pnbr_poseidon_parameters::{Alpha, PoseidonParameters};
use paste::paste;
use ark_ff::vec::Vec;

use crate::{domain_separator, parameters::*};

macro_rules! n_to_one {
    ($n: literal, $n_as_word: literal) => {
        paste! {
            #[doc = "Compute "]
            #[doc = stringify!($n)]
            #[doc = ":1 Poseidon hash of `input`."]
            pub fn [<$n_as_word _to_one_hash>] (input: [Fr; $n]) -> Fr {
                let parameters = [<rate_ $n>]::<Fr>();
                let mut sponge = PoseidonSponge::new(&to_ark_sponge_poseidon_parameters(parameters));
                sponge.absorb(&[ark_ff::vec![domain_separator()], input.to_vec()].concat());
                let result: Vec<Fr> = sponge.squeeze_field_elements(1);
                result[0].clone()
            }
        }
    };
}

n_to_one!(1, "one");
n_to_one!(2, "two");
n_to_one!(4, "four");

fn to_ark_sponge_poseidon_parameters(params: PoseidonParameters<Fr>) -> PoseidonConfig<Fr> {
    let alpha = match params.alpha {
        Alpha::Exponent(exp) => exp as u64,
        Alpha::Inverse => panic!("ark-sponge does not allow inverse alpha"),
    };
    let capacity = 1;
    let rate = params.t - capacity;
    let full_rounds = params.rounds.full();
    let partial_rounds = params.rounds.partial();

    PoseidonConfig {
        full_rounds,
        partial_rounds,
        alpha,
        ark: params.arc.into(),
        mds: params.mds.into(),
        rate,
        capacity,
    }
}
