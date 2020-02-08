use age_plugin::{
    print_new_identity, run_plugin, AgeCallbacks, AgeError, AgePlugin, RecipientStanza,
};
use gumdrop::Options;
use std::fmt;
use std::io;

const PLUGIN_NAME: &str = "unencrypted";
const RECIPIENT_TAG: &str = PLUGIN_NAME;

#[derive(Debug)]
enum Error {
    InvalidIdentity,
    InvalidRecipient,
    UnsupportedRecipientStanza,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidIdentity => write!(f, "Invalid identity"),
            Error::InvalidRecipient => write!(f, "Invalid recipient"),
            Error::UnsupportedRecipientStanza => write!(f, "Unsupported recipient stanza"),
        }
    }
}

impl AgeError for Error {
    fn code(&self) -> u16 {
        // TODO
        1
    }
}

#[derive(Debug)]
struct Plugin;

impl AgePlugin for Plugin {
    type Error = Error;

    fn add_identity(&mut self, plugin_name: &str, identity: &[u8]) -> Result<(), Self::Error> {
        if plugin_name == PLUGIN_NAME && identity.is_empty() {
            // A real plugin would store the identity.
            Ok(())
        } else {
            Err(Error::InvalidIdentity)
        }
    }

    fn wrap_file_key(
        &mut self,
        plugin_name: &str,
        recipient: &[u8],
        file_key: &[u8],
    ) -> Result<RecipientStanza, Self::Error> {
        if plugin_name == PLUGIN_NAME && recipient.is_empty() {
            // A real plugin would wrap the file key here.
            Ok(RecipientStanza {
                tag: RECIPIENT_TAG.to_owned(),
                args: vec!["does".to_owned(), "nothing".to_owned()],
                body: file_key.to_vec(),
            })
        } else {
            Err(Error::InvalidRecipient)
        }
    }

    fn unwrap_file_key(
        &mut self,
        r: RecipientStanza,
        mut callbacks: impl AgeCallbacks,
    ) -> Result<Vec<u8>, Self::Error> {
        if r.tag == RECIPIENT_TAG {
            // A real plugin would attempt to unwrap the file key with the stored
            // identities.
            let _ = callbacks.prompt("This identity does nothing!");
            Ok(r.body)
        } else {
            Err(Error::UnsupportedRecipientStanza)
        }
    }
}

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "run as an age plugin", no_short)]
    run_plugin: bool,
}

fn main() -> io::Result<()> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if opts.run_plugin {
        run_plugin(Plugin)
    } else {
        // A real plugin would generate a new identity here.
        print_new_identity(PLUGIN_NAME, &[], &[])
    }
}
