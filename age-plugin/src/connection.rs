//! Connection handler.

use age_core::format::AgeStanza;
use cookie_factory::SerializeFn;
use secrecy::SecretString;
use std::io::{self, Write};

use crate::{
    format::{write, Command, CMD_SECRET},
    AgeCallbacks, AgeError, RecipientStanza,
};

pub(crate) struct Connection {
    input: io::BufReader<io::Stdin>,
    output: io::Stdout,
}

impl Connection {
    pub(crate) fn new() -> Connection {
        Connection {
            input: io::BufReader::new(io::stdin()),
            output: io::stdout(),
        }
    }

    pub(crate) fn read_command(&mut self) -> io::Result<Command> {
        Command::read(&mut self.input)
    }

    fn write_reply<'a, F: SerializeFn<&'a mut io::Stdout>>(&'a mut self, f: F) -> io::Result<()> {
        cookie_factory::gen_simple(f, &mut self.output)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to write response: {}", e),
                )
            })?
            .flush()
    }

    pub(crate) fn identity_added(&mut self) -> io::Result<()> {
        self.write_reply(write::ok(&AgeStanza {
            tag: "add-identity",
            args: vec![],
            body: vec![0],
        }))
    }

    pub(crate) fn file_key(&mut self, file_key: Vec<u8>) -> io::Result<()> {
        self.write_reply(write::ok(&AgeStanza {
            tag: "file-key",
            args: vec![],
            body: file_key,
        }))
    }

    pub(crate) fn recipient_stanza(&mut self, r: RecipientStanza) -> io::Result<()> {
        let args: Vec<_> = r.args.iter().map(|s| s.as_str()).collect();
        self.write_reply(write::ok(&AgeStanza {
            tag: &r.tag,
            args,
            body: r.body,
        }))
    }

    pub(crate) fn plugin_error<E: AgeError>(&mut self, e: E) -> io::Result<()> {
        self.write_reply(write::error(e.code(), &format!("{}", e)))
    }

    pub(crate) fn invalid_command(&mut self, expected: &[&str]) -> io::Result<()> {
        self.write_reply(write::error(
            20,
            &format!("Invalid command (expected one of {:?}", expected),
        ))
    }
}

pub(crate) struct Callbacks<'a> {
    conn: &'a mut Connection,
}

impl<'a> Callbacks<'a> {
    pub(crate) fn new(conn: &'a mut Connection) -> Self {
        Callbacks { conn }
    }
}

impl<'a> AgeCallbacks for Callbacks<'a> {
    fn prompt(&mut self, message: &str) -> io::Result<()> {
        self.conn.write_reply(write::prompt(message))
    }

    fn request_secret(&mut self, message: &str) -> io::Result<SecretString> {
        self.conn.write_reply(write::request_secret(message))?;
        loop {
            match self.conn.read_command()? {
                Command::Secret(secret) => break Ok(secret),
                _ => self.conn.invalid_command(&[CMD_SECRET])?,
            }
        }
    }
}
