//! Encryption and decryption routines for age.

use rand::{rngs::OsRng, RngCore};
use secrecy::SecretString;
use std::io::{self, Read, Write};
use std::iter;

use crate::{
    error::Error,
    format::{oil_the_joint, scrypt, Header, HeaderV1, RecipientStanza},
    keys::{FileKey, RecipientKey},
    primitives::stream::{PayloadKey, Stream, StreamWriter},
};

#[cfg(feature = "async")]
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod decryptor;

pub(crate) struct Nonce([u8; 16]);

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Nonce {
    fn random() -> Self {
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        Nonce(nonce)
    }

    fn read<R: Read>(input: &mut R) -> io::Result<Self> {
        let mut nonce = [0; 16];
        input.read_exact(&mut nonce)?;
        Ok(Nonce(nonce))
    }

    #[cfg(feature = "async")]
    async fn read_async<R: AsyncRead + Unpin>(input: &mut R) -> io::Result<Self> {
        let mut nonce = [0; 16];
        input.read_exact(&mut nonce).await?;
        Ok(Nonce(nonce))
    }
}

/// Callbacks that might be triggered during decryption.
pub trait Callbacks {
    /// Requests a passphrase to decrypt a key.
    fn request_passphrase(&self, description: &str) -> Option<SecretString>;
}

struct NoCallbacks;

impl Callbacks for NoCallbacks {
    fn request_passphrase(&self, _description: &str) -> Option<SecretString> {
        None
    }
}

/// Handles the various types of age encryption.
enum EncryptorType {
    /// Encryption to a list of recipients identified by keys.
    Keys(Vec<RecipientKey>),
    /// Encryption to a passphrase.
    Passphrase(SecretString),
}

/// Encryptor for creating an age file.
pub struct Encryptor(EncryptorType);

impl Encryptor {
    /// Returns an `Encryptor` that will create an age file encrypted to a list of
    /// recipients.
    pub fn with_recipients(recipients: Vec<RecipientKey>) -> Self {
        Encryptor(EncryptorType::Keys(recipients))
    }

    /// Returns an `Encryptor` that will create an age file encrypted with a passphrase.
    ///
    /// This API should only be used with a passphrase that was provided by (or generated
    /// for) a human. For programmatic use cases, instead generate a [`SecretKey`] and
    /// then use [`Encryptor::with_recipients`].
    ///
    /// [`SecretKey`]: crate::keys::SecretKey
    pub fn with_user_passphrase(passphrase: SecretString) -> Self {
        Encryptor(EncryptorType::Passphrase(passphrase))
    }

    /// Creates the header for this age file.
    fn prepare_header(self) -> (Header, Nonce, PayloadKey) {
        let file_key = FileKey::generate();

        let recipients = match self.0 {
            EncryptorType::Keys(recipients) => recipients
                .iter()
                .map(|key| key.wrap_file_key(&file_key))
                // Keep the joint well oiled!
                .chain(iter::once(oil_the_joint()))
                .collect(),
            EncryptorType::Passphrase(passphrase) => {
                vec![scrypt::RecipientStanza::wrap_file_key(&file_key, &passphrase).into()]
            }
        };

        let header = HeaderV1::new(recipients, file_key.mac_key());
        let nonce = Nonce::random();
        let payload_key = file_key
            .v1_payload_key(&header, &nonce)
            .expect("MAC is correct");

        (Header::V1(header), nonce, payload_key)
    }

    /// Creates a wrapper around a writer that will encrypt its input.
    ///
    /// Returns errors from the underlying writer while writing the header.
    ///
    /// You **MUST** call [`StreamWriter::finish`] when you are done writing, in order to
    /// finish the encryption process. Failing to call [`StreamWriter::finish`] will
    /// result in a truncated file that will fail to decrypt.
    pub fn wrap_output<W: Write>(self, mut output: W) -> io::Result<StreamWriter<W>> {
        let (header, nonce, payload_key) = self.prepare_header();
        header.write(&mut output)?;
        output.write_all(nonce.as_ref())?;
        Ok(Stream::encrypt(payload_key, output))
    }

    /// Creates a wrapper around a writer that will encrypt its input.
    ///
    /// Returns errors from the underlying writer while writing the header.
    ///
    /// You **MUST** call [`StreamWriter::poll_close`] when you are done writing, in order
    /// to finish the encryption process. Failing to call [`StreamWriter::poll_close`]
    /// will result in a truncated file that will fail to decrypt.
    #[cfg(feature = "async")]
    pub async fn wrap_async_output<W: AsyncWrite + Unpin>(
        self,
        mut output: W,
    ) -> io::Result<StreamWriter<W>> {
        let (header, nonce, payload_key) = self.prepare_header();
        header.write_async(&mut output).await?;
        output.write_all(nonce.as_ref()).await?;
        Ok(Stream::encrypt_async(payload_key, output))
    }
}

/// Decryptor for an age file.
pub enum Decryptor<R> {
    /// Decryption with a list of identities.
    Recipients(decryptor::RecipientsDecryptor<R>),
    /// Decryption with a passphrase.
    Passphrase(decryptor::PassphraseDecryptor<R>),
}

impl<R> From<decryptor::RecipientsDecryptor<R>> for Decryptor<R> {
    fn from(decryptor: decryptor::RecipientsDecryptor<R>) -> Self {
        Decryptor::Recipients(decryptor)
    }
}

impl<R> From<decryptor::PassphraseDecryptor<R>> for Decryptor<R> {
    fn from(decryptor: decryptor::PassphraseDecryptor<R>) -> Self {
        Decryptor::Passphrase(decryptor)
    }
}

impl<R> Decryptor<R> {
    fn from_v1_header(input: R, header: HeaderV1, nonce: Nonce) -> Result<Self, Error> {
        // Enforce structural requirements on the v1 header.
        let any_scrypt = header.recipients.iter().any(|r| {
            if let RecipientStanza::Scrypt(_) = r {
                true
            } else {
                false
            }
        });

        if any_scrypt && header.recipients.len() == 1 {
            Ok(decryptor::PassphraseDecryptor::new(input, Header::V1(header), nonce).into())
        } else if !any_scrypt {
            Ok(decryptor::RecipientsDecryptor::new(input, Header::V1(header), nonce).into())
        } else {
            Err(Error::InvalidHeader)
        }
    }
}

impl<R: Read> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    pub fn new(mut input: R) -> Result<Self, Error> {
        let header = Header::read(&mut input)?;

        match header {
            Header::V1(v1_header) => {
                let nonce = Nonce::read(&mut input)?;
                Decryptor::from_v1_header(input, v1_header, nonce)
            }
            Header::Unknown(_) => Err(Error::UnknownFormat),
        }
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    pub async fn new_async(mut input: R) -> Result<Self, Error> {
        let header = Header::read_async(&mut input).await?;

        match header {
            Header::V1(v1_header) => {
                let nonce = Nonce::read_async(&mut input).await?;
                Decryptor::from_v1_header(input, v1_header, nonce)
            }
            Header::Unknown(_) => Err(Error::UnknownFormat),
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use std::io::{BufReader, Read, Write};

    use super::{Decryptor, Encryptor};
    use crate::keys::{Identity, RecipientKey};

    #[cfg(feature = "async")]
    use futures::{
        io::{AsyncRead, AsyncWrite},
        pin_mut,
        task::Poll,
        Future,
    };
    #[cfg(feature = "async")]
    use futures_test::task::noop_context;

    fn recipient_round_trip(recipients: Vec<RecipientKey>, identities: &[Identity]) {
        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::with_recipients(recipients);
        {
            let mut w = e.wrap_output(&mut encrypted).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = match Decryptor::new(&encrypted[..]) {
            Ok(Decryptor::Recipients(d)) => d,
            _ => panic!(),
        };
        let mut r = d.decrypt(identities).unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[cfg(feature = "async")]
    fn recipient_async_round_trip(recipients: Vec<RecipientKey>, identities: &[Identity]) {
        let test_msg = b"This is a test message. For testing.";
        let mut cx = noop_context();

        let mut encrypted = vec![];
        let e = Encryptor::with_recipients(recipients);
        {
            let w = {
                let f = e.wrap_async_output(&mut encrypted);
                pin_mut!(f);

                loop {
                    match f.as_mut().poll(&mut cx) {
                        Poll::Ready(Ok(w)) => break w,
                        Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                        Poll::Pending => panic!("Unexpected Pending"),
                    }
                }
            };
            pin_mut!(w);

            let mut tmp = &test_msg[..];
            loop {
                match w.as_mut().poll_write(&mut cx, &mut tmp) {
                    Poll::Ready(Ok(0)) => break,
                    Poll::Ready(Ok(written)) => tmp = &tmp[written..],
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
            loop {
                match w.as_mut().poll_close(&mut cx) {
                    Poll::Ready(Ok(())) => break,
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
        }

        let d = match {
            let f = Decryptor::new_async(&encrypted[..]);
            pin_mut!(f);

            loop {
                match f.as_mut().poll(&mut cx) {
                    Poll::Ready(Ok(w)) => break w,
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
        } {
            Decryptor::Recipients(d) => d,
            _ => panic!(),
        };

        let decrypted = {
            let mut buf = vec![];
            let r = d.decrypt_async(identities).unwrap();
            pin_mut!(r);

            let mut tmp = [0; 4096];
            loop {
                match r.as_mut().poll_read(&mut cx, &mut tmp) {
                    Poll::Ready(Ok(0)) => break buf,
                    Poll::Ready(Ok(read)) => buf.extend_from_slice(&tmp[..read]),
                    Poll::Ready(Err(e)) => panic!("Unexpected error: {}", e),
                    Poll::Pending => panic!("Unexpected Pending"),
                }
            }
        };

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[test]
    fn x25519_round_trip() {
        let buf = BufReader::new(crate::keys::tests::TEST_SK.as_bytes());
        let sk = Identity::from_buffer(buf).unwrap();
        let pk: RecipientKey = crate::keys::tests::TEST_PK.parse().unwrap();
        recipient_round_trip(vec![pk], &sk);
    }

    #[cfg(feature = "async")]
    #[test]
    fn x25519_async_round_trip() {
        let buf = BufReader::new(crate::keys::tests::TEST_SK.as_bytes());
        let sk = Identity::from_buffer(buf).unwrap();
        let pk: RecipientKey = crate::keys::tests::TEST_PK.parse().unwrap();
        recipient_async_round_trip(vec![pk], &sk);
    }

    #[test]
    fn scrypt_round_trip() {
        let test_msg = b"This is a test message. For testing.";

        let mut encrypted = vec![];
        let e = Encryptor::with_user_passphrase(SecretString::new("passphrase".to_string()));
        {
            let mut w = e.wrap_output(&mut encrypted).unwrap();
            w.write_all(test_msg).unwrap();
            w.finish().unwrap();
        }

        let d = match Decryptor::new(&encrypted[..]) {
            Ok(Decryptor::Passphrase(d)) => d,
            _ => panic!(),
        };
        let mut r = d
            .decrypt(&SecretString::new("passphrase".to_string()), None)
            .unwrap();
        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();

        assert_eq!(&decrypted[..], &test_msg[..]);
    }

    #[test]
    fn ssh_rsa_round_trip() {
        let buf = BufReader::new(crate::ssh::identity::tests::TEST_SSH_RSA_SK.as_bytes());
        let sk = crate::ssh::identity::Identity::from_buffer(buf, None).unwrap();
        let pk: RecipientKey = crate::ssh::recipient::tests::TEST_SSH_RSA_PK
            .parse()
            .unwrap();
        recipient_round_trip(vec![pk], &[sk.into()]);
    }

    #[cfg(feature = "async")]
    #[test]
    fn ssh_rsa_async_round_trip() {
        let buf = BufReader::new(crate::ssh::identity::tests::TEST_SSH_RSA_SK.as_bytes());
        let sk = crate::ssh::identity::Identity::from_buffer(buf, None).unwrap();
        let pk: RecipientKey = crate::ssh::recipient::tests::TEST_SSH_RSA_PK
            .parse()
            .unwrap();
        recipient_async_round_trip(vec![pk], &[sk.into()]);
    }

    #[test]
    fn ssh_ed25519_round_trip() {
        let buf = BufReader::new(crate::ssh::identity::tests::TEST_SSH_ED25519_SK.as_bytes());
        let sk = crate::ssh::identity::Identity::from_buffer(buf, None).unwrap();
        let pk: RecipientKey = crate::ssh::recipient::tests::TEST_SSH_ED25519_PK
            .parse()
            .unwrap();
        recipient_round_trip(vec![pk], &[sk.into()]);
    }

    #[cfg(feature = "async")]
    #[test]
    fn ssh_ed25519_async_round_trip() {
        let buf = BufReader::new(crate::ssh::identity::tests::TEST_SSH_ED25519_SK.as_bytes());
        let sk = crate::ssh::identity::Identity::from_buffer(buf, None).unwrap();
        let pk: RecipientKey = crate::ssh::recipient::tests::TEST_SSH_ED25519_PK
            .parse()
            .unwrap();
        recipient_async_round_trip(vec![pk], &[sk.into()]);
    }
}
