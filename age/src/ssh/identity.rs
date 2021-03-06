use nom::{
    branch::alt,
    bytes::streaming::{is_not, tag},
    character::streaming::newline,
    combinator::{map_opt, opt},
    sequence::{pair, preceded, terminated, tuple},
    IResult,
};
use secrecy::{ExposeSecret, Secret};
use std::fmt;
use std::io;

use super::{read_asn1, read_ssh, write_ssh, EncryptedKey};
use crate::{
    error::Error, format::RecipientStanza, keys::FileKey, protocol::Callbacks,
    util::read::wrapped_str_while_encoded,
};

/// An SSH private key for decrypting an age file.
pub enum UnencryptedKey {
    /// An ssh-rsa private key.
    SshRsa(Vec<u8>, Box<rsa::RSAPrivateKey>),
    /// An ssh-ed25519 key pair.
    SshEd25519(Vec<u8>, Secret<[u8; 64]>),
}

impl UnencryptedKey {
    /// Returns:
    /// - `Some(Ok(file_key))` on success.
    /// - `Some(Err(e))` if a decryption error occurs.
    /// - `None` if the [`RecipientStanza`] does not match this key.
    pub(crate) fn unwrap_file_key(
        &self,
        stanza: &RecipientStanza,
    ) -> Option<Result<FileKey, Error>> {
        match (self, stanza) {
            (UnencryptedKey::SshRsa(ssh_key, sk), RecipientStanza::SshRsa(r)) => {
                r.unwrap_file_key(ssh_key, sk)
            }
            (UnencryptedKey::SshEd25519(ssh_key, privkey), RecipientStanza::SshEd25519(r)) => {
                r.unwrap_file_key(ssh_key, privkey.expose_secret())
            }
            _ => None,
        }
    }
}

/// A key that we know how to parse, but that we do not support.
///
/// The Display impl provides details for each unsupported key as to why we don't support
/// it, and how a user can migrate to a supported key.
#[derive(Clone, Debug)]
pub enum UnsupportedKey {
    /// An encrypted `PEM` key.
    EncryptedPem,
    /// An encrypted SSH key using a specific cipher.
    EncryptedSsh(String),
}

impl UnsupportedKey {
    /// Prints details about this unsupported identity.
    pub fn display(&self, f: &mut fmt::Formatter, filename: Option<&str>) -> fmt::Result {
        if let Some(name) = filename {
            writeln!(f, "Unsupported SSH identity: {}", name)?;
            writeln!(f)?;
        }
        match self {
            UnsupportedKey::EncryptedPem => {
                let message = [
                    "Insecure Encrypted Key Format",
                    "-----------------------------",
                    "Prior to OpenSSH version 7.8, if a password was set when generating a new",
                    "DSA, ECDSA, or RSA key, ssh-keygen would encrypt the key using the encrypted",
                    "PEM format. This encryption format is insecure and should no longer be used.",
                    "",
                    "You can migrate your key to the encrypted SSH private key format (which has",
                    "been supported by OpenSSH since version 6.5, released in January 2014) by",
                    "changing its passphrase with the following command:",
                    "",
                    "    ssh-keygen -o -p",
                    "",
                    "If you are using an OpenSSH version between 6.5 and 7.7 (such as the default",
                    "OpenSSH provided on Ubuntu 18.04 LTS), you can use the following command to",
                    "force keys to be generated using the new format:",
                    "",
                    "    ssh-keygen -o",
                ];
                for line in &message {
                    writeln!(f, "{}", line)?;
                }
            }
            UnsupportedKey::EncryptedSsh(cipher) => {
                let currently_unsupported = format!("currently-unsupported cipher ({}).", cipher);
                let new_issue = format!(
                    "https://github.com/str4d/rage/issues/new?title=Support%20OpenSSH%20key%20encryption%20cipher%20{}",
                    cipher,
                );
                let message = [
                    "Unsupported Cipher for Encrypted SSH Key",
                    "----------------------------------------",
                    "OpenSSH internally supports several different ciphers for encrypted keys,",
                    "but it has only ever directly generated a few of them. rage supports all",
                    "ciphers that ssh-keygen might generate, and is being updated on a",
                    "case-by-case basis with support for non-standard ciphers. Your key uses a",
                    &currently_unsupported,
                    "",
                    "If you would like support for this key type, please open an issue here:",
                    "",
                    &new_issue,
                ];
                for line in &message {
                    writeln!(f, "{}", line)?;
                }
            }
        }
        Ok(())
    }
}

/// An SSH private key for decrypting an age file.
pub enum Identity {
    /// An unencrypted key.
    Unencrypted(UnencryptedKey),
    /// An encrypted key.
    Encrypted(EncryptedKey),
    /// A key that we know how to parse, but that we do not support.
    Unsupported(UnsupportedKey),
}

impl From<UnencryptedKey> for Identity {
    fn from(key: UnencryptedKey) -> Self {
        Identity::Unencrypted(key)
    }
}

impl From<EncryptedKey> for Identity {
    fn from(key: EncryptedKey) -> Self {
        Identity::Encrypted(key)
    }
}

impl From<UnsupportedKey> for Identity {
    fn from(key: UnsupportedKey) -> Self {
        Identity::Unsupported(key)
    }
}

impl Identity {
    /// Parses one or more identities from a buffered input containing valid UTF-8.
    ///
    /// `filename` is the path to the file that the input is reading from, if any.
    pub fn from_buffer<R: io::BufRead>(mut data: R, filename: Option<String>) -> io::Result<Self> {
        let mut buf = String::new();
        loop {
            match ssh_identity(&buf) {
                Ok((_, mut identity)) => {
                    // If we know the filename, cache it.
                    if let Identity::Encrypted(key) = &mut identity {
                        key.filename = filename;
                    }

                    break Ok(identity);
                }
                Err(nom::Err::Incomplete(nom::Needed::Size(_))) => {
                    if data.read_line(&mut buf)? == 0 {
                        break Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "incomplete SSH identity in file",
                        ));
                    };
                }
                Err(_) => {
                    break Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid SSH identity",
                    ));
                }
            }
        }
    }

    pub(crate) fn unwrap_file_key(
        &self,
        stanza: &RecipientStanza,
        callbacks: &dyn Callbacks,
    ) -> Option<Result<FileKey, Error>> {
        match self {
            Identity::Unencrypted(key) => key.unwrap_file_key(stanza),
            Identity::Encrypted(enc) => {
                let passphrase = callbacks.request_passphrase(&format!(
                    "Type passphrase for OpenSSH key '{}'",
                    enc.filename
                        .as_ref()
                        .map(|s| s.as_str())
                        .unwrap_or_default()
                ))?;
                let decrypted = match enc.decrypt(passphrase) {
                    Ok(d) => d,
                    Err(e) => return Some(Err(e)),
                };
                decrypted.unwrap_file_key(stanza)
            }
            Identity::Unsupported(_) => None,
        }
    }
}

fn rsa_pem_encryption_header(input: &str) -> IResult<&str, &str> {
    preceded(
        tuple((tag("Proc-Type: 4,ENCRYPTED"), newline, tag("DEK-Info: "))),
        terminated(is_not("\n"), newline),
    )(input)
}

fn rsa_privkey(input: &str) -> IResult<&str, Identity> {
    preceded(
        pair(tag("-----BEGIN RSA PRIVATE KEY-----"), newline),
        terminated(
            map_opt(
                pair(
                    opt(terminated(rsa_pem_encryption_header, newline)),
                    wrapped_str_while_encoded(base64::STANDARD),
                ),
                |(enc_header, privkey)| {
                    if enc_header.is_some() {
                        Some(UnsupportedKey::EncryptedPem.into())
                    } else {
                        read_asn1::rsa_privkey(&privkey).ok().map(|(_, privkey)| {
                            let mut ssh_key = vec![];
                            cookie_factory::gen(
                                write_ssh::rsa_pubkey(&privkey.to_public_key()),
                                &mut ssh_key,
                            )
                            .expect("can write into a Vec");
                            UnencryptedKey::SshRsa(ssh_key, Box::new(privkey)).into()
                        })
                    }
                },
            ),
            pair(newline, tag("-----END RSA PRIVATE KEY-----")),
        ),
    )(input)
}

fn openssh_privkey(input: &str) -> IResult<&str, Identity> {
    preceded(
        pair(tag("-----BEGIN OPENSSH PRIVATE KEY-----"), newline),
        terminated(
            map_opt(wrapped_str_while_encoded(base64::STANDARD), |privkey| {
                read_ssh::openssh_privkey(&privkey).ok().map(|(_, key)| key)
            }),
            pair(newline, tag("-----END OPENSSH PRIVATE KEY-----")),
        ),
    )(input)
}

pub(crate) fn ssh_identity(input: &str) -> IResult<&str, Identity> {
    alt((rsa_privkey, openssh_privkey))(input)
}

#[cfg(test)]
pub(crate) mod tests {
    use secrecy::{ExposeSecret, Secret};
    use std::io::BufReader;

    use super::Identity;
    use crate::{
        keys::FileKey,
        ssh::recipient::{
            tests::{TEST_SSH_ED25519_PK, TEST_SSH_RSA_PK},
            Recipient,
        },
    };

    pub(crate) const TEST_SSH_RSA_SK: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxO5yF0xjbmkQTfbaCP8DQC7kHnPJr5bdIie6Nzmg9lL6Chye
0vK5iJ+BYkA1Hnf1WnNzoVIm3otZPkwZptertkY95JYFmTiA4IvHeL1yiOTd2AYc
a947EPpM9XPomeM/7U7c99OvuCuOl1YlTFsMsoPY/NiZ+NZjgMvb3XgyH0OXy3mh
qp+SsJU+tRjZGfqM1iv2TZUCJTQnKF8YSVCyLPV67XM1slQQHmtZ5Q6NFhzg3j8a
CY5rDR66UF5+Zn/TvN8bNdKn01I50VLePI0ZnnRcuLXK2t0Bpkk0NymZ3vsF10m9
HCKVyxr2Y0Ejx4BtYXOK97gaYks73rBi7+/VywIDAQABAoIBADGsf8TWtOH9yGoS
ES9hu90ttsbjqAUNhdv+r18Mv0hC5+UzEPDe3uPScB1rWrrDwXS+WHVhtoI+HhWz
tmi6UArbLvOA0Aq1EPUS7Q7Mop5bNIYwDG09EiMXL+BeC1b91nsygFRW5iULf502
0pOvB8XjshEdRcFZuqGbSmtTzTjLLxYS/aboBtZLHrH4cRlFMpHWCSuJng8Psahp
SnJbkjL7fHG81dlH+M3qm5EwdDJ1UmNkBfoSfGRs2pupk2cSJaL+SPkvNX+6Xyoy
yvfnbJzKUTcV6rf+0S0P0yrWK3zRK9maPJ1N60lFui9LvFsunCLkSAluGKiMwEjb
fm40F4kCgYEA+QzIeIGMwnaOQdAW4oc7hX5MgRPXJ836iALy56BCkZpZMjZ+VKpk
8P4E1HrEywpgqHMox08hfCTGX3Ph6fFIlS1/mkLojcgkrqmg1IrRvh8vvaZqzaAf
GKEhxxRta9Pvm44E2nUY97iCKzE3Vfh+FIyQLRuc+0COu49Me4HPtBUCgYEAym1T
vNZKPfC/eTMh+MbWMsQArOePdoHQyRC38zeWrLaDFOUVzwzEvCQ0IzSs0PnLWkZ4
xx60wBg5ZdU4iH4cnOYgjavQrbRFrCmZ1KDUm2+NAMw3avcLQqu41jqzyAlkktUL
fZzyqHIBmKYLqut5GslkGnQVg6hB4psutHhiel8CgYA3yy9WH9/C6QBxqgaWdSlW
fLby69j1p+WKdu6oCXUgXW3CHActPIckniPC3kYcHpUM58+o5wdfYnW2iKWB3XYf
RXQiwP6MVNwy7PmE5Byc9Sui1xdyPX75648/pEnnMDGrraNUtYsEZCd1Oa9l6SeF
vv/Fuzvt5caUKkQ+HxTDCQKBgFhqUiXr7zeIvQkiFVeE+a/ovmbHKXlYkCoSPFZm
VFCR00VAHjt2V0PaCE/MRSNtx61hlIVcWxSAQCnDbNLpSnQZa+SVRCtqzve4n/Eo
YlSV75+GkzoMN4XiXXRs5XOc7qnXlhJCiBac3Segdv4rpZTWm/uV8oOz7TseDtNS
tai/AoGAC0CiIJAzmmXscXNS/stLrL9bb3Yb+VZi9zN7Cb/w7B0IJ35N5UOFmKWA
QIGpMU4gh6p52S1eLttpIf2+39rEDzo8pY6BVmEp3fKN3jWmGS4mJQ31tWefupC+
fGNu+wyKxPnSU3svsuvrOdwwDKvfqCNyYK878qKAAaBqbGT1NJ8=
-----END RSA PRIVATE KEY-----";

    pub(crate) const TEST_SSH_ED25519_SK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML
agAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ
AAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz
1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=
-----END OPENSSH PRIVATE KEY-----";

    #[test]
    fn ssh_rsa_round_trip() {
        let buf = BufReader::new(TEST_SSH_RSA_SK.as_bytes());
        let identity = Identity::from_buffer(buf, None).unwrap();
        let sk = match identity {
            Identity::Unencrypted(key) => key,
            _ => panic!("key should be unencrypted"),
        };
        let pk: Recipient = TEST_SSH_RSA_PK.parse().unwrap();

        let file_key = FileKey(Secret::new([12; 16]));

        let wrapped = pk.wrap_file_key(&file_key);
        let unwrapped = sk.unwrap_file_key(&wrapped);
        assert_eq!(
            unwrapped.unwrap().unwrap().0.expose_secret(),
            file_key.0.expose_secret()
        );
    }

    #[test]
    fn ssh_ed25519_round_trip() {
        let buf = BufReader::new(TEST_SSH_ED25519_SK.as_bytes());
        let identity = Identity::from_buffer(buf, None).unwrap();
        let sk = match identity {
            Identity::Unencrypted(key) => key,
            _ => panic!("key should be unencrypted"),
        };
        let pk: Recipient = TEST_SSH_ED25519_PK.parse().unwrap();

        let file_key = FileKey(Secret::new([12; 16]));

        let wrapped = pk.wrap_file_key(&file_key);
        let unwrapped = sk.unwrap_file_key(&wrapped);
        assert_eq!(
            unwrapped.unwrap().unwrap().0.expose_secret(),
            file_key.0.expose_secret()
        );
    }
}
