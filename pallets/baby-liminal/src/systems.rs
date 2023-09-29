use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use codec::{Decode, Encode};
use frame_support::{log::error, PalletError};
use scale_info::TypeInfo;

/// Possible errors from the verification process.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Decode, Encode, TypeInfo, PalletError)]
pub enum VerificationError {
    /// The verifying key was malformed.
    ///
    /// May occur only for some non-universal system.
    MalformedVerifyingKey,
    /// There was an error in the underlying holographic IOP. For details, consult your logs.
    ///
    /// May occur only for some universal system.
    AHPError,
    /// There was an error in the underlying polynomial commitment. For details, consult your logs.
    ///
    /// May occur only for some universal system.
    PolynomialCommitmentError,
    /// Unexpected error has occurred. Check your logs.
    UnexpectedError,
}

impl From<SynthesisError> for VerificationError {
    fn from(syn_err: SynthesisError) -> Self {
        match syn_err {
            SynthesisError::MalformedVerifyingKey => VerificationError::MalformedVerifyingKey,
            _ => {
                error!("Unexpected SynthesisError variant: {syn_err}");
                VerificationError::UnexpectedError
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Decode, Encode, TypeInfo)]
pub enum ProvingSystem {
    Groth16,
}

pub(super) trait VerifyingSystem {
    type CircuitField: CanonicalDeserialize;
    type Proof: CanonicalDeserialize;
    type VerifyingKey: CanonicalDeserialize;

    fn verify(
        key: &Self::VerifyingKey,
        input: &[Self::CircuitField],
        proof: &Self::Proof,
        randomness: &[u8],
    ) -> Result<bool, VerificationError>;
}

/// Common pairing engine.
pub type DefaultPairingEngine = ark_bls12_381::Bls12_381;
/// Common scalar field.
pub type DefaultCircuitField = ark_bls12_381::Fr;

pub(super) struct Groth16;
impl VerifyingSystem for Groth16 {
    type CircuitField = DefaultCircuitField;
    type Proof = ark_groth16::Proof<DefaultPairingEngine>;
    type VerifyingKey = ark_groth16::VerifyingKey<DefaultPairingEngine>;

    fn verify(
        key: &Self::VerifyingKey,
        input: &[Self::CircuitField],
        proof: &Self::Proof,
        _: &[u8],
    ) -> Result<bool, VerificationError> {
        ark_groth16::Groth16::<_, LibsnarkReduction>::verify(key, input, proof).map_err(Into::into)
    }
}
