use age_core::format::AgeStanza;
use cookie_factory::SerializeFn;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{ChildStdin, ChildStdout};
use std::process::{Command, Stdio};
use zeroize::Zeroize;

use crate::{format::plugin::RecipientStanza, keys::FileKey};

/// Possible responses from an age plugin.
#[derive(Debug)]
enum Response<'a> {
    /// Request was successful.
    Ok(AgeStanza<'a>),
    /// Request could not be fulfilled.
    Err { code: u16, description: String },
}

struct Connection {
    output: ChildStdin,
    input: BufReader<ChildStdout>,
    buffer: String,
}

impl Connection {
    fn open(plugin_name: &str) -> io::Result<Self> {
        let binary_name = format!("age-plugin-{}", plugin_name);
        let binary = which::which(binary_name).expect("TODO: errors");
        let process = Command::new(binary)
            .arg("--run-plugin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let output = process.stdin.expect("could open stdin");
        let input = BufReader::new(process.stdout.expect("could open stdin"));
        Ok(Connection {
            output,
            input,
            buffer: String::new(),
        })
    }

    fn write_command<'a, F: SerializeFn<&'a mut ChildStdin>>(&'a mut self, f: F) -> io::Result<()> {
        cookie_factory::gen_simple(f, &mut self.output)
            .expect("TODO: errors")
            .flush()
    }

    fn read_response(&mut self) -> io::Result<Response> {
        // We are finished with any prior response.
        self.buffer.zeroize();
        self.buffer.clear();

        loop {
            match read::server_response(self.buffer.as_bytes()) {
                // We can't return the response here, because we need to be able to mutate
                // self.buffer inside the loop.
                Ok(_) => break,
                Err(nom::Err::Incomplete(_)) => {
                    if self.input.read_line(&mut self.buffer)? == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "incomplete response",
                        ));
                    };
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid response",
                    ));
                }
            }
        }

        // Now that we know the buffer contains a valid response, we re-parse so that we
        // can return an immutable lifetime.
        Ok(read::server_response(self.buffer.as_bytes())
            .map(|(_, r)| r)
            .expect("Is valid"))
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // TODO: Maybe have an explicit close command?
    }
}

pub(crate) struct KeyWrapper(Connection);

impl KeyWrapper {
    pub(crate) fn for_plugin(plugin_name: &str) -> io::Result<Self> {
        Connection::open(plugin_name).map(KeyWrapper)
    }

    pub(crate) fn wrap_file_key(
        &mut self,
        file_key: &FileKey,
        recipient: &str,
    ) -> io::Result<RecipientStanza> {
        self.0
            .write_command(write::wrap_file_key(recipient, file_key))?;
        match self.0.read_response()? {
            Response::Ok(stanza) => Ok(RecipientStanza::from_stanza(stanza)),
            Response::Err { code, description } => {
                // TODO: errors
                Err(io::Error::new(io::ErrorKind::Other, description))
            }
        }
    }
}

mod read {
    use age_core::format::read::age_stanza;
    use nom::{
        character::complete::newline,
        combinator::map_opt,
        sequence::{pair, terminated},
        IResult,
    };

    use super::Response;

    #[inline]
    fn stringify(body: Vec<u8>) -> Option<String> {
        String::from_utf8(body).ok()
    }

    pub(super) fn server_response(input: &[u8]) -> IResult<&[u8], Response> {
        terminated(
            map_opt(age_stanza, |mut response| {
                match (response.tag, &response.args[..]) {
                    ("ok", a) if a.len() >= 1 => {
                        let stanza_tag = response.args.remove(0);
                        response.tag = stanza_tag;
                        Some(Response::Ok(response))
                    }
                    ("error", [code]) => {
                        let code = u16::from_str_radix(code, 10).ok()?;
                        stringify(response.body)
                            .map(|description| Response::Err { code, description })
                    }
                    _ => None,
                }
            }),
            pair(newline, newline),
        )(input)
    }
}

mod write {
    use age_core::format::write::age_stanza;
    use cookie_factory::{combinator::string, sequence::tuple, SerializeFn, WriteContext};
    use secrecy::ExposeSecret;
    use std::io::Write;

    use crate::keys::FileKey;

    fn command<'a, W: 'a + Write>(
        tag: &'a str,
        args: &'a [&'a str],
        body: &'a [u8],
    ) -> impl SerializeFn<W> + 'a {
        tuple((age_stanza(tag, args, &body), string("\n\n")))
    }

    pub(crate) fn wrap_file_key<'a, W: 'a + Write>(
        recipient: &'a str,
        file_key: &'a FileKey,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let args = &[recipient];
            let writer = command("wrap-file-key", args, file_key.0.expose_secret());
            writer(w)
        }
    }
}
