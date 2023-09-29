use liminal_ark_relation_macro::snark_relation;

/// 'Vote' relation for the Vote-Shielder application.
///
/// It expresses the facts that:
///  - `note` is a prefix of the result of hashing together `token_id`, `token_amount`,
///    `trapdoor` and `nullifier`
///  - `first_vote` and `second_vote` sums up to `token_amount`
///  - `first_vote_hash` is hash of `first_vote` encryption with `vote_randomness` randomness
///  - `second_vote_hash` is hash of `second_vote` encryption with `vote_randomness` randomness
/// Additionally, the relation has two constant inputs, `max_path_len` which specifies upper bound
/// for the length of the merkle path (which is ~the height of the tree, ±1) and `vote_bases` which
/// are the constants used during the vote encryption
#[snark_relation]
mod relation {

    #[cfg(feature = "circuit")]
    use {
        crate::shielder::{
            check_merkle_proof, note_var::NoteVarBuilder, path_shape_var::PathShapeVar,
            CircuitField,
        },
        ark_ec::AffineRepr,
        ark_ff::BigInteger256,
        ark_ff::{
            fields::field_hashers::{DefaultFieldHasher, HashToField},
            PrimeField,
        },
        ark_r1cs_std::R1CSVar,
        ark_r1cs_std::{
            alloc::{
                AllocVar,
                AllocationMode::{Input, Witness},
            },
            eq::EqGadget,
            fields::fp::FpVar,
        },
        ark_relations::ns,
        ark_serialize::CanonicalSerialize,
        ark_std::ops::Add,
        sha2::Sha256,
    };

    use crate::shielder::{
        convert_bases, convert_hash, convert_vec,
        types::{
            BackendEncryptedVote, BackendLeafIndex, BackendMerklePath, BackendMerkleRoot,
            BackendNote, BackendNullifier, BackendTokenAmount, BackendTokenId, BackendTrapdoor,
            BackendVote, BackendVoteBases, BackendVoteRandomness, FrontendEncryptedVote,
            FrontendLeafIndex, FrontendMerklePath, FrontendMerkleRoot, FrontendNote,
            FrontendNullifier, FrontendTokenAmount, FrontendTokenId, FrontendTrapdoor,
            FrontendVote, FrontendVoteBases, FrontendVoteRandomness,
        },
    };

    #[relation_object_definition]
    #[derive(Clone, Debug)]
    struct VoteRelation {
        #[constant]
        pub max_path_len: u8,
        #[constant(frontend_type = "FrontendVoteBases", parse_with = "convert_bases")]
        pub vote_bases: BackendVoteBases,

        // Public inputs
        #[public_input(frontend_type = "FrontendTokenId")]
        pub token_id: BackendTokenId,
        #[public_input(frontend_type = "FrontendNullifier", parse_with = "convert_hash")]
        pub nullifier: BackendNullifier,
        #[public_input(frontend_type = "FrontendTokenAmount")]
        pub token_amount: BackendTokenAmount,
        #[public_input(frontend_type = "FrontendEncryptedVote", parse_with = "convert_hash")]
        pub first_vote_hash: BackendEncryptedVote,
        #[public_input(frontend_type = "FrontendEncryptedVote", parse_with = "convert_hash")]
        pub second_vote_hash: BackendEncryptedVote,
        #[public_input(frontend_type = "FrontendMerkleRoot", parse_with = "convert_hash")]
        pub merkle_root: BackendMerkleRoot,

        // Private inputs.
        #[private_input(frontend_type = "FrontendTrapdoor", parse_with = "convert_hash")]
        pub trapdoor: BackendTrapdoor,
        #[private_input(frontend_type = "FrontendVote")]
        pub first_vote: BackendVote,
        #[private_input(frontend_type = "FrontendVote")]
        pub second_vote: BackendVote,
        #[private_input(frontend_type = "FrontendVoteRandomness", parse_with = "convert_hash")]
        pub vote_randomness: BackendVoteRandomness,
        #[private_input(frontend_type = "FrontendMerklePath", parse_with = "convert_vec")]
        pub merkle_path: BackendMerklePath,
        #[private_input(frontend_type = "FrontendLeafIndex")]
        pub leaf_index: BackendLeafIndex,
        #[private_input(frontend_type = "FrontendNote", parse_with = "convert_hash")]
        pub note: BackendNote,
    }

    #[cfg(feature = "circuit")]
    #[circuit_definition]
    fn generate_constraints() {
        //------------------------------
        // Check the note arguments.
        //------------------------------

        let note = NoteVarBuilder::new(cs.clone())
            .with_token_id(self.token_id(), Input)?
            .with_nullifier(self.nullifier(), Input)?
            .with_token_amount(self.token_amount(), Input)?
            .with_trapdoor(self.trapdoor(), Witness)?
            .with_note(self.note(), Witness)?
            .build()?;

        //------------------------
        // Check the vote value.
        //------------------------

        let first_vote_hash =
            FpVar::new_input(ns!(cs, "first vote hash"), || self.first_vote_hash())?;
        let second_vote_hash =
            FpVar::new_input(ns!(cs, "second vote hash"), || self.second_vote_hash())?;

        let first_vote = FpVar::new_witness(ns!(cs, "first vote"), || match self.first_vote() {
            Ok(v) => Ok(CircuitField::from(*v)),
            Err(e) => Err(e),
        })?;
        let second_vote =
            FpVar::new_witness(ns!(cs, "second vote"), || match self.second_vote() {
                Ok(v) => Ok(CircuitField::from(*v)),
                Err(e) => Err(e),
            })?;
        let vote_sum = first_vote.clone().add(second_vote.clone());
        vote_sum.enforce_equal(&note.token_amount.into())?;

        let vote_randomness =
            FpVar::new_witness(ns!(cs, "randomness vote"), || self.vote_randomness())?;

        let bases = self.vote_bases();

        let first_hash = bases[0]
            .mul_bigint(vote_randomness.value().unwrap_or_default().into_bigint())
            .add(bases[1].mul_bigint(BigInteger256::from(first_vote.value().unwrap_or_default())));
        let second_hash = bases[2]
            .mul_bigint(vote_randomness.value().unwrap_or_default().into_bigint())
            .add(bases[3].mul_bigint(BigInteger256::from(second_vote.value().unwrap_or_default())));

        let mut hash = [0u8; 48];
        let hasher = <DefaultFieldHasher<Sha256> as HashToField<CircuitField>>::new(&[1, 2, 3]);

        first_hash
            .serialize_compressed(&mut hash[..])
            .expect("succesfully serialize");
        let first_hash_var = FpVar::new_witness(ns!(cs, "first hash var"), || {
            Ok::<CircuitField, _>(hasher.hash_to_field(&hash, 1)[0])
        })?;
        first_hash_var.enforce_equal(&first_vote_hash)?;

        second_hash
            .serialize_compressed(&mut hash[..])
            .expect("succesfully serialize");
        let second_hash_var = FpVar::new_witness(ns!(cs, "second hash var"), || {
            Ok::<CircuitField, _>(hasher.hash_to_field(&hash, 1)[0])
        })?;
        second_hash_var.enforce_equal(&second_vote_hash)?;

        //------------------------
        // Check the merkle proof.
        //------------------------
        let merkle_root = FpVar::new_input(ns!(cs, "merkle root"), || self.merkle_root())?;
        let path_shape = PathShapeVar::new_witness(ns!(cs, "path shape"), || {
            Ok((*self.max_path_len(), self.leaf_index().cloned()))
        })?;

        check_merkle_proof(
            merkle_root,
            path_shape,
            note.note,
            self.merkle_path().cloned().unwrap_or_default(),
            *self.max_path_len(),
            cs,
        )
    }
}

#[cfg(all(test, feature = "circuit"))]
mod tests {

    use ark_bls12_381::Bls12_381;
    use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_snark::SNARK;
    use ark_std::{rand::SeedableRng, One};

    use super::*;
    use crate::shielder::{
        note::{compute_note, compute_parent_hash},
        types::{
            FrontendNote, FrontendNullifier, FrontendTokenAmount, FrontendTokenId, FrontendTrapdoor,
        },
    };

    const MAX_PATH_LEN: u8 = 4;
    const VOTE_BASES: [[u8; 48]; 4] = [
        [
            131, 243, 22, 251, 27, 15, 154, 154, 252, 137, 52, 42, 231, 183, 121, 207, 68, 95, 68,
            69, 244, 238, 227, 27, 58, 108, 44, 150, 223, 140, 129, 232, 31, 152, 214, 153, 240,
            95, 130, 13, 132, 10, 101, 131, 236, 124, 12, 44,
        ],
        [
            153, 79, 94, 143, 147, 208, 228, 13, 192, 64, 24, 57, 66, 193, 85, 11, 195, 75, 28,
            217, 165, 46, 233, 4, 104, 89, 98, 228, 229, 161, 118, 59, 199, 47, 89, 93, 60, 84,
            126, 107, 97, 183, 40, 255, 177, 20, 52, 140,
        ],
        [
            170, 102, 22, 74, 123, 164, 5, 124, 121, 139, 107, 175, 157, 91, 212, 41, 60, 183, 33,
            138, 222, 56, 117, 34, 45, 87, 244, 111, 197, 10, 199, 246, 122, 78, 75, 81, 145, 211,
            131, 106, 162, 251, 14, 168, 47, 119, 102, 169,
        ],
        [
            178, 43, 151, 216, 24, 165, 67, 133, 253, 118, 49, 69, 225, 146, 160, 252, 192, 121, 8,
            170, 211, 191, 186, 248, 70, 255, 103, 115, 159, 176, 219, 76, 86, 143, 188, 54, 131,
            49, 236, 214, 72, 12, 34, 69, 66, 151, 223, 11,
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

    #[test]
    fn vote_constraints_correctness() {
        let circuit = get_circuit_with_full_input();

        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        if !is_satisfied {
            println!("{:?}", cs.which_is_unsatisfied());
        }

        assert!(is_satisfied);
    }

    #[test]
    fn vote_proving_procedure() {
        let circuit_without_input =
            VoteRelationWithoutInput::new(MAX_PATH_LEN, VOTE_BASES.to_vec());

        let mut rng = ark_std::rand::rngs::StdRng::from_rng(ark_std::test_rng()).unwrap();

        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit_without_input, &mut rng).unwrap();

        let circuit = get_circuit_with_full_input();

        let proof = Groth16::<_, LibsnarkReduction>::prove(&pk, circuit, &mut rng).unwrap();

        let circuit = VoteRelationWithPublicInput::from(get_circuit_with_full_input());
        let input = circuit.serialize_public_input();
        let valid_proof = Groth16::<_, LibsnarkReduction>::verify(&vk, &input, &proof).unwrap();
        assert!(valid_proof);
    }

    #[test]
    fn cannot_vote_partially_sub() {
        let circuit_without_input =
            VoteRelationWithoutInput::new(MAX_PATH_LEN, VOTE_BASES.to_vec());

        let mut rng = ark_std::rand::rngs::StdRng::from_rng(ark_std::test_rng()).unwrap();

        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit_without_input, &mut rng).unwrap();

        let mut circuit = get_circuit_with_full_input();

        circuit.token_amount = circuit.token_amount - BackendTokenAmount::one();

        let proof = Groth16::<_, LibsnarkReduction>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        let circuit = VoteRelationWithPublicInput::from(circuit);
        let input = circuit.serialize_public_input();
        let valid_proof = Groth16::<_, LibsnarkReduction>::verify(&vk, &input, &proof).unwrap();
        assert!(!valid_proof);
    }

    #[test]
    fn cannot_vote_partially_add() {
        let circuit_without_input =
            VoteRelationWithoutInput::new(MAX_PATH_LEN, VOTE_BASES.to_vec());

        let mut rng = ark_std::rand::rngs::StdRng::from_rng(ark_std::test_rng()).unwrap();

        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit_without_input, &mut rng).unwrap();

        let mut circuit = get_circuit_with_full_input();

        circuit.token_amount = circuit.token_amount + BackendTokenAmount::one();

        let proof = Groth16::<_, LibsnarkReduction>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        let circuit = VoteRelationWithPublicInput::from(circuit);
        let input = circuit.serialize_public_input();
        let valid_proof = Groth16::<_, LibsnarkReduction>::verify(&vk, &input, &proof).unwrap();
        assert!(!valid_proof);
    }

    #[test]
    fn cannot_vote_with_wrong_vote_hash() {
        let circuit_without_input =
            VoteRelationWithoutInput::new(MAX_PATH_LEN, VOTE_BASES.to_vec());

        let mut rng = ark_std::rand::rngs::StdRng::from_rng(ark_std::test_rng()).unwrap();

        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit_without_input, &mut rng).unwrap();

        let mut circuit = get_circuit_with_full_input();

        circuit.first_vote_hash = circuit.first_vote_hash + BackendEncryptedVote::one();

        let proof = Groth16::<_, LibsnarkReduction>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        let circuit = VoteRelationWithPublicInput::from(circuit);
        let input = circuit.serialize_public_input();
        let valid_proof = Groth16::<_, LibsnarkReduction>::verify(&vk, &input, &proof).unwrap();
        assert!(!valid_proof);
    }

    #[test]
    fn cannot_vote_with_wrong_vote_randomness() {
        let circuit_without_input =
            VoteRelationWithoutInput::new(MAX_PATH_LEN, VOTE_BASES.to_vec());

        let mut rng = ark_std::rand::rngs::StdRng::from_rng(ark_std::test_rng()).unwrap();

        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit_without_input, &mut rng).unwrap();

        let mut circuit = get_circuit_with_full_input();

        circuit.vote_randomness = circuit.vote_randomness + BackendVoteRandomness::one();

        let proof = Groth16::<_, LibsnarkReduction>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        let circuit = VoteRelationWithPublicInput::from(circuit);
        let input = circuit.serialize_public_input();
        let valid_proof = Groth16::<_, LibsnarkReduction>::verify(&vk, &input, &proof).unwrap();
        assert!(!valid_proof);
    }
}
