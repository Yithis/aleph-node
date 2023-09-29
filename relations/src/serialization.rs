use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::{vec, vec::Vec};

pub fn serialize<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut bytes = vec![0; t.serialized_size(Compress::Yes)];
    t.serialize_compressed(&mut bytes[..])
        .expect("Failed to serialize");
    bytes.to_vec()
}
