use ring::{
    agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256},
    rand::SystemRandom,
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

use super::RecipientStanza;
use crate::{
    error::Error,
    keys::{piv_to_str, FileKey},
    primitives::{aead_encrypt, hkdf, p256::PublicKey},
    util::read::base64_arg,
};

pub(super) const PIV_RECIPIENT_TAG: &str = "piv";
const PIV_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/piv";

const TAG_BYTES: usize = 4;
const EPK_BYTES: usize = 33;
const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

pub(crate) fn piv_tag(pk: &PublicKey) -> [u8; TAG_BYTES] {
    let tag = Sha256::digest(piv_to_str(pk).as_bytes());
    (&tag[0..TAG_BYTES]).try_into().expect("length is correct")
}

#[derive(Debug)]
pub(crate) struct RecipientLine {
    tag: [u8; TAG_BYTES],
    epk: PublicKey,
    encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl RecipientLine {
    pub(super) fn from_stanza(stanza: RecipientStanza<'_>) -> Option<Self> {
        if stanza.tag != PIV_RECIPIENT_TAG {
            return None;
        }

        let tag = base64_arg(stanza.args.get(0)?, [0; TAG_BYTES])?;
        let epk = PublicKey::from_bytes(&base64_arg(stanza.args.get(1)?, vec![0; EPK_BYTES])?)?;

        Some(RecipientLine {
            tag,
            epk,
            encrypted_file_key: stanza.body[..].try_into().ok()?,
        })
    }

    pub(crate) fn wrap_file_key(file_key: &FileKey, pk: &PublicKey) -> Self {
        let rng = SystemRandom::new();

        let esk = EphemeralPrivateKey::generate(&ECDH_P256, &rng).expect("TODO handle failing RNG");
        let epk = PublicKey::from_bytes(esk.compute_public_key().expect("TODO").as_ref())
            .expect("epk is valid");

        let pk_uncompressed = pk.decompress();
        let pk_ring = UnparsedPublicKey::new(&ECDH_P256, pk_uncompressed.as_bytes());

        let enc_key = agree_ephemeral(esk, &pk_ring, Error::DecryptionFailed, |shared_secret| {
            let mut salt = vec![];
            salt.extend_from_slice(epk.as_bytes());
            salt.extend_from_slice(pk.as_bytes());

            Ok(hkdf(&salt, PIV_RECIPIENT_KEY_LABEL, shared_secret))
        })
        .expect("keys are correct");

        let encrypted_file_key = {
            let mut key = [0; ENCRYPTED_FILE_KEY_BYTES];
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.0.expose_secret()));
            key
        };

        RecipientLine {
            tag: piv_tag(pk),
            epk,
            encrypted_file_key,
        }
        .into()
    }
}

pub(super) mod write {
    use cookie_factory::{combinator::string, sequence::tuple, SerializeFn};
    use std::io::Write;

    use super::*;
    use crate::util::write::encoded_data;

    pub(crate) fn recipient_line<'a, W: 'a + Write>(r: &RecipientLine) -> impl SerializeFn<W> + 'a {
        tuple((
            string(PIV_RECIPIENT_TAG),
            string(" "),
            encoded_data(&r.tag),
            string(" "),
            encoded_data(r.epk.as_bytes()),
            string("\n"),
            encoded_data(&r.encrypted_file_key),
        ))
    }
}
