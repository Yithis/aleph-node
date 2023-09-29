use ark_bls12_381::Bls12_381;
use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
//
// cargo bench
//
use criterion::{criterion_group, criterion_main, Criterion};
use liminal_ark_poseidon::hash;
pub use liminal_ark_relations::shielder::{
    VoteRelationWithFullInput, VoteRelationWithPublicInput, VoteRelationWithoutInput,
    WithdrawRelationWithFullInput, WithdrawRelationWithPublicInput, WithdrawRelationWithoutInput,
};
use liminal_ark_relations::{
    environment::CircuitField,
    shielder::{
        compute_note, compute_parent_hash,
        types::{
            FrontendAccount, FrontendNote, FrontendNullifier, FrontendTokenAmount, FrontendTokenId,
            FrontendTrapdoor,
        },
    },
};

/*fn preimage(c: &mut Criterion) {
    let circuit_withouth_input = PreimageRelationWithoutInput::new();

    let preimage = CircuitField::from(7u64);
    let image = hash::one_to_one_hash([preimage]);
    let frontend_image: [u64; 4] = image.0 .0;

    let mut rng: ark_std::rand::rngs::StdRng =
        ark_std::rand::rngs::StdRng::from_rng(ark_std::test_rng()).unwrap();
    let (pk, _) =
        Groth16::<Bls12_381>::circuit_specific_setup(circuit_withouth_input, &mut rng).unwrap();

    c.bench_function("preimage", |f| {
        f.iter(|| {
            let full_circuit = PreimageRelationWithFullInput::new(frontend_image, preimage.0 .0);
            let _ = Groth16::<_, LibsnarkReduction>::prove(&pk, full_circuit, &mut rng).unwrap();
        })
    });
}*/

const MAX_PATH_LEN: u8 = 4;
const VOTE_BASES: [[u8; 48]; 4] = [
    [
        131, 243, 22, 251, 27, 15, 154, 154, 252, 137, 52, 42, 231, 183, 121, 207, 68, 95, 68, 69,
        244, 238, 227, 27, 58, 108, 44, 150, 223, 140, 129, 232, 31, 152, 214, 153, 240, 95, 130,
        13, 132, 10, 101, 131, 236, 124, 12, 44,
    ],
    [
        153, 79, 94, 143, 147, 208, 228, 13, 192, 64, 24, 57, 66, 193, 85, 11, 195, 75, 28, 217,
        165, 46, 233, 4, 104, 89, 98, 228, 229, 161, 118, 59, 199, 47, 89, 93, 60, 84, 126, 107,
        97, 183, 40, 255, 177, 20, 52, 140,
    ],
    [
        170, 102, 22, 74, 123, 164, 5, 124, 121, 139, 107, 175, 157, 91, 212, 41, 60, 183, 33, 138,
        222, 56, 117, 34, 45, 87, 244, 111, 197, 10, 199, 246, 122, 78, 75, 81, 145, 211, 131, 106,
        162, 251, 14, 168, 47, 119, 102, 169,
    ],
    [
        178, 43, 151, 216, 24, 165, 67, 133, 253, 118, 49, 69, 225, 146, 160, 252, 192, 121, 8,
        170, 211, 191, 186, 248, 70, 255, 103, 115, 159, 176, 219, 76, 86, 143, 188, 54, 131, 49,
        236, 214, 72, 12, 34, 69, 66, 151, 223, 11,
    ],
];

fn get_circuit_with_full_input() -> VoteRelationWithFullInput {
    let token_id: FrontendTokenId = 1;

    let trapdoor: FrontendTrapdoor = [17; 4];
    let nullifier: FrontendNullifier = [19; 4];
    let token_amount: FrontendTokenAmount = 10;

    let note = compute_note(token_id, token_amount, trapdoor, nullifier);

    //                                          merkle root
    //                placeholder                                        x
    //        1                          x                     x                         x
    //   2        3                x          x            x       x                 x       x
    // 4  *5*   6   7            x   x      x   x        x   x   x   x             x   x   x   x
    let leaf_index = 5;

    let zero_note = FrontendNote::default(); // x

    let sibling_note = compute_note(0, 1, [2; 4], [3; 4]); // 4
    let parent_note = compute_parent_hash(sibling_note, note); // 2
    let uncle_note = compute_note(4, 5, [6; 4], [7; 4]); // 3
    let grandpa_root = compute_parent_hash(parent_note, uncle_note); // 1

    let placeholder = compute_parent_hash(grandpa_root, zero_note);
    let merkle_root = compute_parent_hash(placeholder, zero_note);

    let merkle_path = vec![sibling_note, uncle_note];
    let first_vote_hash = [
        u64::from_le_bytes([95, 118, 94, 194, 76, 7, 244, 22]),
        u64::from_le_bytes([181, 185, 82, 140, 2, 142, 33, 74]),
        u64::from_le_bytes([208, 106, 110, 159, 26, 119, 204, 212]),
        u64::from_le_bytes([21, 64, 144, 30, 79, 32, 155, 109]),
    ];
    let second_vote_hash = [
        u64::from_le_bytes([225, 96, 214, 217, 80, 171, 210, 210]),
        u64::from_le_bytes([166, 242, 51, 116, 214, 221, 73, 242]),
        u64::from_le_bytes([245, 254, 3, 90, 10, 230, 236, 235]),
        u64::from_le_bytes([144, 246, 169, 128, 17, 180, 99, 79]),
    ];

    let first_vote = 4;
    let second_vote = 6;
    let vote_randomness = [
        u64::from_le_bytes([214, 193, 0, 0, 95, 196, 2, 12]),
        u64::from_le_bytes([44, 149, 6, 42, 226, 28, 112, 138]),
        u64::from_le_bytes([149, 210, 138, 181, 127, 215, 145, 109]),
        u64::from_le_bytes([112, 42, 201, 171, 240, 193, 127, 105]),
    ];

    VoteRelationWithFullInput::new(
        MAX_PATH_LEN,
        VOTE_BASES.to_vec(),
        token_id,
        nullifier,
        token_amount,
        first_vote_hash,
        second_vote_hash,
        merkle_root,
        trapdoor,
        first_vote,
        second_vote,
        vote_randomness,
        merkle_path,
        leaf_index,
        note,
    )
}

pub fn generate_keys() -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
    let circuit_without_input = VoteRelationWithoutInput::new(MAX_PATH_LEN, VOTE_BASES.to_vec());

    let mut rng = ark_std::rand::rngs::StdRng::from_rng(ark_std::test_rng()).unwrap();

    Groth16::<Bls12_381>::circuit_specific_setup(circuit_without_input, &mut rng).unwrap()
}

pub fn generate_proof(pk: ProvingKey<Bls12_381>) -> Proof<Bls12_381> {
    let circuit = get_circuit_with_full_input();

    let mut rng = ark_std::rand::rngs::StdRng::from_rng(ark_std::test_rng()).unwrap();

    Groth16::<_, LibsnarkReduction>::prove(&pk, circuit, &mut rng).unwrap()
}

pub fn verify_proof(proof: &Proof<Bls12_381>, vk: &VerifyingKey<Bls12_381>) {
    let circuit = VoteRelationWithPublicInput::from(get_circuit_with_full_input());
    let input = circuit.serialize_public_input();
    let valid_proof = Groth16::<_, LibsnarkReduction>::verify(&vk, &input, &proof).unwrap();
}

fn withdraw_get_circuit_with_full_input() -> WithdrawRelationWithFullInput {
    let token_id: FrontendTokenId = 1;

    let old_trapdoor: FrontendTrapdoor = [17; 4];
    let old_nullifier: FrontendNullifier = [19; 4];
    let whole_token_amount: FrontendTokenAmount = 10;

    let new_trapdoor: FrontendTrapdoor = [27; 4];
    let new_nullifier: FrontendNullifier = [87; 4];
    let new_token_amount: FrontendTokenAmount = 3;

    let token_amount_out: FrontendTokenAmount = 7;

    let old_note = compute_note(token_id, whole_token_amount, old_trapdoor, old_nullifier);
    let new_note = compute_note(token_id, new_token_amount, new_trapdoor, new_nullifier);

    //                                          merkle root
    //                placeholder                                        x
    //        1                          x                     x                         x
    //   2        3                x          x            x       x                 x       x
    // 4  *5*   6   7            x   x      x   x        x   x   x   x             x   x   x   x
    let leaf_index = 5;

    let zero_note = FrontendNote::default(); // x

    let sibling_note = compute_note(0, 1, [2; 4], [3; 4]); // 4
    let parent_note = compute_parent_hash(sibling_note, old_note); // 2
    let uncle_note = compute_note(4, 5, [6; 4], [7; 4]); // 3
    let grandpa_root = compute_parent_hash(parent_note, uncle_note); // 1

    let placeholder = compute_parent_hash(grandpa_root, zero_note);
    let merkle_root = compute_parent_hash(placeholder, zero_note);

    let merkle_path = vec![sibling_note, uncle_note];

    let fee: FrontendTokenAmount = 1;
    let recipient: FrontendAccount = [
        212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88,
        133, 76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
    ];

    WithdrawRelationWithFullInput::new(
        MAX_PATH_LEN,
        fee,
        recipient,
        token_id,
        old_nullifier,
        new_note,
        token_amount_out,
        merkle_root,
        old_trapdoor,
        new_trapdoor,
        new_nullifier,
        merkle_path,
        leaf_index,
        old_note,
        whole_token_amount,
        new_token_amount,
    )
}

pub fn withdraw_generate_keys() -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
    let circuit_without_input = WithdrawRelationWithoutInput::new(MAX_PATH_LEN);

    let mut rng = ark_std::rand::rngs::StdRng::from_rng(ark_std::test_rng()).unwrap();

    Groth16::<Bls12_381>::circuit_specific_setup(circuit_without_input, &mut rng).unwrap()
}

pub fn withdraw_generate_proof(pk: ProvingKey<Bls12_381>) -> Proof<Bls12_381> {
    let circuit = withdraw_get_circuit_with_full_input();

    let mut rng = ark_std::rand::rngs::StdRng::from_rng(ark_std::test_rng()).unwrap();

    Groth16::<_, LibsnarkReduction>::prove(&pk, circuit, &mut rng).unwrap()
}

pub fn withdraw_verify_proof(proof: &Proof<Bls12_381>, vk: &VerifyingKey<Bls12_381>) {
    let circuit = WithdrawRelationWithPublicInput::from(withdraw_get_circuit_with_full_input());
    let input = circuit.serialize_public_input();
    let valid_proof = Groth16::<_, LibsnarkReduction>::verify(&vk, &input, &proof).unwrap();
}

fn vote(c: &mut Criterion) {
    let circuit = get_circuit_with_full_input();

    //println!("circuit srs size is {}", &circuit.srs_size().unwrap());

    c.bench_function("vote/keygen", |b| b.iter(|| generate_keys()));

    let (pk, vk) = generate_keys();
    print_sizes("verify key", &vk);

    c.bench_function("vote/prover", |b| b.iter(|| generate_proof(pk.clone())));

    let proof = generate_proof(pk);
    print_sizes("proof", &proof);

    c.bench_function("vote/verifier", |b| b.iter(|| verify_proof(&proof, &vk)));
}

fn withdraw(c: &mut Criterion) {
    let circuit = get_circuit_with_full_input();

    //println!("circuit srs size is {}", &circuit.srs_size().unwrap());

    c.bench_function("withdraw/keygen", |b| b.iter(|| withdraw_generate_keys()));

    let (pk, vk) = withdraw_generate_keys();
    print_sizes("verify key", &vk);

    c.bench_function("withdraw/prover", |b| {
        b.iter(|| withdraw_generate_proof(pk.clone()))
    });

    let proof = withdraw_generate_proof(pk);
    print_sizes("proof", &proof);

    c.bench_function("withdraw/verifier", |b| {
        b.iter(|| withdraw_verify_proof(&proof, &vk))
    });
}

fn print_sizes<T: CanonicalSerialize>(name: &str, obj: &T) {
    println!(
        "{} uncompressed size is {} and compressed size is {}",
        name,
        obj.serialized_size(Compress::No),
        obj.serialized_size(Compress::Yes),
    );
}

criterion_group! {
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().significance_level(0.1).sample_size(100);
    targets = vote
}
criterion_main!(benches);
