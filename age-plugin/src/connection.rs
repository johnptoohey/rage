//! Connection handler.

use age_core::format::AgeStanza;
use cookie_factory::SerializeFn;
use std::io::{self, Write};

use crate::{
    format::{write, Command},
    AgeError, RecipientStanza,
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
}
