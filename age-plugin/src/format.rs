use secrecy::SecretString;
use std::io::{self, BufRead};

use crate::RecipientStanza;

pub(crate) const CMD_ADD_IDENTITY: &str = "add-identity";
pub(crate) const CMD_SECRET: &str = "secret";
pub(crate) const CMD_UNWRAP_FILE_KEY: &str = "unwrap-file-key";
pub(crate) const CMD_WRAP_FILE_KEY: &str = "wrap-file-key";

#[derive(Debug)]
pub(crate) enum Command {
    AddIdentity {
        plugin_name: String,
        identity: Vec<u8>,
    },
    WrapFileKey {
        plugin_name: String,
        recipient: Vec<u8>,
        file_key: Vec<u8>,
    },
    UnwrapFileKey(RecipientStanza),
    Secret(SecretString),
}

impl Command {
    pub(crate) fn read<R: BufRead>(mut input: R) -> io::Result<Self> {
        let mut buf = String::new();

        loop {
            match read::client_command(buf.as_bytes()) {
                Ok((_, r)) => break Ok(r),
                Err(nom::Err::Incomplete(_)) => {
                    if input.read_line(&mut buf)? == 0 {
                        break Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "incomplete command",
                        ));
                    };
                }
                Err(_) => {
                    break Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid command",
                    ));
                }
            }
        }
    }
}

mod read {
    use age_core::format::read::age_stanza;
    use bech32::FromBase32;
    use nom::{
        character::streaming::newline,
        combinator::map_opt,
        sequence::{pair, terminated},
        IResult,
    };
    use secrecy::SecretString;

    use super::{Command, CMD_ADD_IDENTITY, CMD_SECRET, CMD_UNWRAP_FILE_KEY, CMD_WRAP_FILE_KEY};
    use crate::{RecipientStanza, PLUGIN_RECIPIENT_PREFIX, PLUGIN_SECRET_PREFIX};

    #[inline]
    fn stringify(body: Vec<u8>) -> Option<String> {
        String::from_utf8(body).ok()
    }

    fn parse_bech32(s: &str) -> Option<(String, Vec<u8>)> {
        bech32::decode(&s)
            .ok()
            .and_then(|(hrp, data)| Vec::from_base32(&data).ok().map(|d| (hrp, d)))
    }

    fn parse_identity(identity: &str) -> Option<(String, Vec<u8>)> {
        let (hrp, data) = parse_bech32(identity)?;

        if hrp.starts_with(PLUGIN_SECRET_PREFIX) && hrp.ends_with('-') {
            let fragment = hrp.split_at(PLUGIN_SECRET_PREFIX.len()).1;
            Some((fragment.split_at(fragment.len() - 1).0.to_owned(), data))
        } else {
            None
        }
    }

    fn parse_recipient(recipient: &str) -> Option<(String, Vec<u8>)> {
        let (hrp, data) = parse_bech32(recipient)?;

        if hrp.starts_with(PLUGIN_RECIPIENT_PREFIX) {
            Some((
                hrp.split_at(PLUGIN_RECIPIENT_PREFIX.len()).1.to_owned(),
                data,
            ))
        } else {
            None
        }
    }

    pub(super) fn client_command(input: &[u8]) -> IResult<&[u8], Command> {
        terminated(
            map_opt(age_stanza, |command| {
                match (command.tag, &command.args[..]) {
                    (CMD_ADD_IDENTITY, []) => stringify(command.body)
                        .and_then(|s| parse_identity(&s))
                        .map(|(plugin_name, identity)| Command::AddIdentity {
                            plugin_name,
                            identity,
                        }),
                    (CMD_SECRET, []) => stringify(command.body)
                        .map(SecretString::new)
                        .map(Command::Secret),
                    (CMD_UNWRAP_FILE_KEY, a) if !a.is_empty() => {
                        Some(Command::UnwrapFileKey(RecipientStanza {
                            tag: command.args[0].to_owned(),
                            args: command.args.into_iter().skip(1).map(String::from).collect(),
                            body: command.body,
                        }))
                    }
                    (CMD_WRAP_FILE_KEY, [recipient]) => {
                        parse_recipient(recipient).map(|(plugin_name, recipient)| {
                            Command::WrapFileKey {
                                plugin_name,
                                recipient,
                                file_key: command.body,
                            }
                        })
                    }
                    _ => None,
                }
            }),
            pair(newline, newline),
        )(input)
    }
}

pub(crate) mod write {
    use age_core::format::{write::age_stanza, AgeStanza};
    use cookie_factory::{combinator::string, sequence::tuple, SerializeFn, WriteContext};
    use std::io::Write;
    use std::iter;

    fn response<'a, W: 'a + Write>(
        tag: &'a str,
        args: &'a [&'a str],
        body: &'a [u8],
    ) -> impl SerializeFn<W> + 'a {
        tuple((age_stanza(tag, args, &body), string("\n\n")))
    }

    pub(crate) fn ok<'a, W: 'a + Write>(stanza: &'a AgeStanza<'a>) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let args: Vec<_> = iter::once(stanza.tag)
                .chain(stanza.args.iter().cloned())
                .collect();
            let writer = response("ok", &args, &stanza.body);
            writer(w)
        }
    }

    pub(crate) fn error<'a, W: 'a + Write>(
        code: u16,
        description: &'a str,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let code = format!("{}", code);
            let args = &[code.as_str()];
            let writer = response("error", args, description.as_bytes());
            writer(w)
        }
    }

    pub(crate) fn prompt<'a, W: 'a + Write>(message: &'a str) -> impl SerializeFn<W> + 'a {
        response("prompt", &[], message.as_bytes())
    }

    pub(crate) fn request_secret<'a, W: 'a + Write>(message: &'a str) -> impl SerializeFn<W> + 'a {
        response("request-secret", &[], message.as_bytes())
    }
}
