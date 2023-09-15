use clap::ValueEnum;
use liminal_ark_relations::{
    environment::{CircuitField, Groth16, NonUniversalSystem, ProvingSystem, RawKeys},
    serialization::serialize,
    CanonicalDeserialize, ConstraintSynthesizer,
};

/// All available non universal proving systems.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, ValueEnum)]
pub enum NonUniversalProvingSystem {
    Groth16,
}

/// Any proving system.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum SomeProvingSystem {
    NonUniversal(NonUniversalProvingSystem),
}

/// API available only for non universal proving systems.
impl NonUniversalProvingSystem {
    pub fn id(&self) -> String {
        format!("{:?}", self).to_lowercase()
    }

    /// Generates proving and verifying key for `circuit`. Returns serialized keys.
    pub fn generate_keys<C: ConstraintSynthesizer<CircuitField>>(&self, circuit: C) -> RawKeys {
        match self {
            NonUniversalProvingSystem::Groth16 => self._generate_keys::<_, Groth16>(circuit),
        }
    }

    fn _generate_keys<C: ConstraintSynthesizer<CircuitField>, S: NonUniversalSystem>(
        &self,
        circuit: C,
    ) -> RawKeys {
        let (pk, vk) = S::generate_keys(circuit);
        RawKeys {
            pk: serialize(&pk),
            vk: serialize(&vk),
        }
    }
}

/// Common API for all systems.
impl SomeProvingSystem {
    pub fn id(&self) -> String {
        match self {
            SomeProvingSystem::NonUniversal(s) => s.id(),
        }
    }

    /// Generates proof for `circuit` using proving key `pk`. Returns serialized proof.
    pub fn prove<C: ConstraintSynthesizer<CircuitField>>(
        &self,
        circuit: C,
        pk: Vec<u8>,
    ) -> Vec<u8> {
        use SomeProvingSystem::*;

        match self {
            NonUniversal(NonUniversalProvingSystem::Groth16) => {
                Self::_prove::<_, Groth16>(circuit, pk)
            }
        }
    }

    fn _prove<C: ConstraintSynthesizer<CircuitField>, S: ProvingSystem>(
        circuit: C,
        pk: Vec<u8>,
    ) -> Vec<u8> {
        let pk = <S::ProvingKey>::deserialize_compressed(&*pk)
            .expect("Failed to deserialize proving key");
        let proof = S::prove(&pk, circuit);
        serialize(&proof)
    }

    /// Verifies proof.
    pub fn verify(&self, vk: Vec<u8>, proof: Vec<u8>, input: Vec<u8>) -> bool {
        use SomeProvingSystem::*;

        match self {
            NonUniversal(NonUniversalProvingSystem::Groth16) => {
                Self::_verify::<Groth16>(vk, proof, input)
            }
        }
    }

    fn _verify<S: ProvingSystem>(vk: Vec<u8>, proof: Vec<u8>, input: Vec<u8>) -> bool {
        let vk = <S::VerifyingKey>::deserialize_compressed(&*vk)
            .expect("Failed to deserialize verifying key");
        let proof =
            <S::Proof>::deserialize_compressed(&*proof).expect("Failed to deserialize proof");
        let input = <Vec<CircuitField>>::deserialize_compressed(&*input)
            .expect("Failed to deserialize public input");

        S::verify(&vk, &proof, input)
            .map_err(|_| "Failed to verify proof")
            .unwrap()
    }
}
