//! Structs for handling YubiKeys.

use bech32::ToBase32;
use elliptic_curve::weierstrass::PublicKey as EcPublicKey;
use p256::NistP256;
use secrecy::{ExposeSecret, Secret};
use std::convert::TryInto;
use yubikey_piv::{
    certificate::{Certificate, PublicKeyInfo},
    key::{decrypt_data, AlgorithmId, SlotId},
    yubikey::Serial,
    YubiKey,
};

use super::{piv_tag, RecipientLine, PIV_RECIPIENT_KEY_LABEL};
use crate::{
    error::Error,
    keys::{FileKey, RecipientKey, YUBIKEY_STUB_PREFIX},
    primitives::{aead_decrypt, hkdf, p256::PublicKey},
    protocol::Callbacks,
};

/// A reference to an age key stored in a YubiKey.
#[derive(Debug, PartialEq)]
pub struct Stub {
    pub(crate) serial: Serial,
    pub(crate) slot: SlotId,
    pub(crate) tag: [u8; 4],
}

impl Stub {
    /// Returns a key stub and recipient for this `(Serial, SlotId, PublicKey)` tuple.
    ///
    /// Does not check that the `PublicKey` matches the given `(Serial, SlotId)` tuple;
    /// this is checked at decryption time.
    pub fn new(
        serial: Serial,
        slot: SlotId,
        pubkey: &EcPublicKey<NistP256>,
    ) -> Result<(Self, RecipientKey), Error> {
        PublicKey::from_pubkey(pubkey)
            .ok_or(Error::InvalidRecipient)
            .map(|pk| {
                (
                    Stub {
                        serial,
                        slot,
                        tag: piv_tag(&pk),
                    },
                    RecipientKey::Piv(pk),
                )
            })
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let serial = Serial::from(u32::from_le_bytes(bytes[0..4].try_into().unwrap()));
        let slot: SlotId = bytes[4].try_into().ok()?;
        Some(Stub {
            serial,
            slot,
            tag: bytes[5..9].try_into().unwrap(),
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9);
        bytes.extend_from_slice(&self.serial.0.to_le_bytes());
        bytes.push(self.slot.into());
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    /// Serializes this YubiKey stub as a string.
    pub fn to_str(&self) -> String {
        bech32::encode(YUBIKEY_STUB_PREFIX, self.to_bytes().to_base32())
            .expect("HRP is valid")
            .to_uppercase()
    }

    pub(crate) fn unwrap_file_key(
        &self,
        line: &RecipientLine,
        callbacks: &dyn Callbacks,
    ) -> Option<Result<FileKey, Error>> {
        if self.tag != line.tag {
            return None;
        }

        Some((|| {
            let mut yubikey = YubiKey::open()?;

            // Read the pubkey from the YubiKey slot and check it still matches.
            let cert = Certificate::read(&mut yubikey, self.slot)?;
            let pk = match cert.subject_pki() {
                PublicKeyInfo::EcP256(pubkey) => {
                    if let Some(pk) = PublicKey::from_pubkey(pubkey) {
                        if piv_tag(&pk) == self.tag {
                            Ok(pk)
                        } else {
                            Err(Error::KeyMismatch)
                        }
                    } else {
                        Err(Error::InvalidRecipient)
                    }
                }
                _ => Err(Error::KeyMismatch),
            }?;

            let pin = callbacks
                .request_passphrase(&format!(
                    "Enter PIN for YubiKey with serial {}",
                    self.serial
                ))
                .ok_or(Error::KeyDecryptionFailed)?;
            yubikey.verify_pin(pin.expose_secret().as_bytes())?;

            let shared_secret = decrypt_data(
                &mut yubikey,
                line.epk.decompress().as_bytes(),
                AlgorithmId::EccP256,
                self.slot,
            )?;

            let mut salt = vec![];
            salt.extend_from_slice(line.epk.as_bytes());
            salt.extend_from_slice(pk.as_bytes());

            let enc_key = hkdf(&salt, PIV_RECIPIENT_KEY_LABEL, shared_secret.as_ref());

            // A failure to decrypt is fatal, because we assume that we won't
            // encounter 32-bit collisions on the key tag embedded in the header.
            aead_decrypt(&enc_key, &line.encrypted_file_key)
                .map(|pt| {
                    // It's ours!
                    let mut file_key = [0; 16];
                    file_key.copy_from_slice(&pt);
                    FileKey(Secret::new(file_key))
                })
                .map_err(Error::from)
        })())
    }
}

#[cfg(test)]
mod tests {
    use yubikey_piv::{key::SlotId, Serial};

    use super::Stub;

    #[test]
    fn stub_round_trip() {
        let stub = Stub {
            serial: Serial::from(42),
            slot: SlotId::KeyManagement,
            tag: [7; 4],
        };

        let encoded = stub.to_bytes();
        assert_eq!(Stub::from_bytes(&encoded), Some(stub));
    }
}
