use age::cli_common::file_io;
use gumdrop::Options;
use log::error;
use secrecy::ExposeSecret;
use std::io::Write;

#[cfg(feature = "yubikey")]
use rand::{rngs::OsRng, RngCore};
#[cfg(feature = "yubikey")]
use secrecy::SecretString;
#[cfg(feature = "yubikey")]
use std::convert::TryFrom;
#[cfg(feature = "yubikey")]
use std::error::Error;
#[cfg(feature = "yubikey")]
use yubikey_piv::{
    certificate::{Certificate, PublicKeyInfo},
    key::{generate as yubikey_generate, AlgorithmId, Key, RetiredSlotId, SlotId},
    policy::{PinPolicy, TouchPolicy},
    MgmKey, YubiKey,
};

#[cfg(feature = "yubikey")]
const USABLE_SLOTS: [SlotId; 20] = [
    SlotId::Retired(RetiredSlotId::R1),
    SlotId::Retired(RetiredSlotId::R2),
    SlotId::Retired(RetiredSlotId::R3),
    SlotId::Retired(RetiredSlotId::R4),
    SlotId::Retired(RetiredSlotId::R5),
    SlotId::Retired(RetiredSlotId::R6),
    SlotId::Retired(RetiredSlotId::R7),
    SlotId::Retired(RetiredSlotId::R8),
    SlotId::Retired(RetiredSlotId::R9),
    SlotId::Retired(RetiredSlotId::R10),
    SlotId::Retired(RetiredSlotId::R11),
    SlotId::Retired(RetiredSlotId::R12),
    SlotId::Retired(RetiredSlotId::R13),
    SlotId::Retired(RetiredSlotId::R14),
    SlotId::Retired(RetiredSlotId::R15),
    SlotId::Retired(RetiredSlotId::R16),
    SlotId::Retired(RetiredSlotId::R17),
    SlotId::Retired(RetiredSlotId::R18),
    SlotId::Retired(RetiredSlotId::R19),
    SlotId::Retired(RetiredSlotId::R20),
];

#[derive(Debug, Options)]
struct AgeOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "set up a YubiKey", no_short)]
    yubikey: bool,

    #[options(help = "output to OUTPUT (default stdout)")]
    output: Option<String>,
}

#[cfg(feature = "yubikey")]
fn yubikey_setup() -> Result<Option<(SecretString, String)>, age::Error> {
    use age::cli_common::read_secret;
    use dialoguer::{Confirmation, Input, Select};

    let mut yubikey = YubiKey::open()?;
    let keys = Key::list(&mut yubikey)?;

    let slots: Vec<_> = USABLE_SLOTS
        .iter()
        .enumerate()
        .map(|(i, slot)| {
            // Use 1-indexing in the UI for niceness
            let i = i + 1;

            let occupied = keys.iter().find(|key| key.slot() == *slot);
            if let Some(key) = occupied {
                format!(
                    "Slot {} ({}, Algorithm: {:?})",
                    i,
                    key.certificate().subject(),
                    key.certificate().subject_pki().algorithm(),
                )
            } else {
                format!("Slot {} (Empty)", i)
            }
        })
        .collect();

    loop {
        let slot = match Select::new()
            .with_prompt("Use the up/down arrow keys to select a PIV slot (q to quit)")
            .items(&slots)
            .default(0)
            .interact_opt()?
        {
            Some(slot) => USABLE_SLOTS[slot],
            None => return Ok(None),
        };

        if let Some(key) = keys.iter().find(|key| key.slot() == slot) {
            match key.certificate().subject_pki() {
                PublicKeyInfo::EcP256(pubkey) => {
                    if Confirmation::new()
                        .with_text(&format!("Use existing key in {:?} slot?", slot))
                        .interact()?
                    {
                        let (stub, recipient) =
                            age::yubikey::Stub::new(yubikey.serial(), key.slot(), pubkey)?;

                        break Ok(Some((
                            SecretString::new(stub.to_str()),
                            recipient.to_string(),
                        )));
                    }
                }
                PublicKeyInfo::Rsa { .. } | PublicKeyInfo::EcP384(_) => {
                    eprintln!("Error: age requires P-256 for YubiKeys.");
                    break Ok(None);
                }
            }
        } else {
            let pin_policy = match Select::new()
                .with_prompt("Select a PIN policy")
                .items(&[
                    "Always (A PIN is required for every decryption, if set)",
                    "Once   (A PIN is required once per session, if set)",
                    "Never  (A PIN is NOT required to decrypt)",
                ])
                .default(1)
                .interact_opt()?
            {
                Some(0) => PinPolicy::Always,
                Some(1) => PinPolicy::Once,
                Some(2) => PinPolicy::Never,
                Some(_) => unreachable!(),
                None => return Ok(None),
            };

            let touch_policy = match Select::new()
                .with_prompt("Select a touch policy")
                .items(&[
                    "Always (A physical touch is required for every decryption),",
                    "Cached (A physical touch is required for decryption, and is cached for 15 seconds)",
                    "Never  (A physical touch is NOT required to decrypt)",
                ])
                .default(0)
                .interact_opt()?
            {
                Some(0) => TouchPolicy::Always,
                Some(1) => TouchPolicy::Cached,
                Some(2) => TouchPolicy::Never,
                Some(_) => unreachable!(),
                None => return Ok(None),
            };

            if Confirmation::new()
                .with_text(&format!("Generate new key in {:?} slot?", slot))
                .interact()?
            {
                let mgm_input = Input::<String>::new()
                    .with_prompt("Enter the management key [blank to use default key]")
                    .allow_empty(true)
                    .interact()?;
                yubikey.authenticate(if mgm_input.is_empty() {
                    MgmKey::default()
                } else {
                    match hex::decode(mgm_input) {
                        Ok(mgm_bytes) => match MgmKey::try_from(&mgm_bytes[..]) {
                            Ok(mgm_key) => mgm_key,
                            Err(_) => {
                                error!("Incorrect management key size");
                                return Ok(None);
                            }
                        },
                        Err(_) => {
                            error!("Management key must be a hex string");
                            return Ok(None);
                        }
                    }
                })?;

                if let PinPolicy::Never = pin_policy {
                    // No need to enter PIN
                } else {
                    let pin = read_secret(
                        &format!("Enter PIN for YubiKey with serial {}", yubikey.serial()),
                        "PIN",
                        None,
                    )?;
                    yubikey.verify_pin(pin.expose_secret().as_bytes())?;
                }

                if let TouchPolicy::Never = touch_policy {
                    // No need to touch YubiKey
                } else {
                    eprintln!("Please touch the YubiKey");
                }

                // Generate a new key in the selected slot.
                let generated = yubikey_generate(
                    &mut yubikey,
                    slot,
                    AlgorithmId::EccP256,
                    pin_policy,
                    touch_policy,
                )?;

                let mut serial = [0; 20];
                OsRng.fill_bytes(&mut serial);

                let cert = Certificate::generate_self_signed(
                    &mut yubikey,
                    slot,
                    serial,
                    None,
                    "rage-keygen".to_owned(),
                    generated,
                )?;

                match cert.subject_pki() {
                    PublicKeyInfo::EcP256(pubkey) => {
                        let (stub, recipient) =
                            age::yubikey::Stub::new(yubikey.serial(), slot, pubkey)?;

                        break Ok(Some((
                            SecretString::new(stub.to_str()),
                            recipient.to_string(),
                        )));
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
}

fn main() {
    env_logger::builder().format_timestamp(None).init();

    let opts = AgeOptions::parse_args_default_or_exit();

    let mut output =
        match file_io::OutputWriter::new(opts.output, file_io::OutputFormat::Text, 0o600) {
            Ok(output) => output,
            Err(e) => {
                error!("Failed to open output: {}", e);
                return;
            }
        };

    let (privkey, pubkey) = if opts.yubikey {
        #[cfg(feature = "yubikey")]
        match yubikey_setup() {
            Ok(Some(res)) => res,
            Ok(None) => return,
            Err(e) => match e {
                age::Error::YubiKey(e) => {
                    eprintln!("Error while communicating with YubiKey: {}", e);
                    if let Some(inner) = e.source() {
                        eprintln!("Cause: {}", inner);
                    }
                    return;
                }
                _ => {
                    eprintln!("Failed to set up YubiKey: {}", e);
                    return;
                }
            },
        }

        #[cfg(not(feature = "yubikey"))]
        {
            eprintln!("Error: rage-keygen was not built with YubiKey support.");
            eprintln!("Use '--features yubikey' when building.");
            return;
        }
    } else {
        let sk = age::keys::SecretKey::generate();
        (sk.to_string(), sk.to_public().to_string())
    };

    if let Err(e) = (|| {
        writeln!(
            output,
            "# created: {}",
            chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )?;
        writeln!(output, "# {}", pubkey)?;
        writeln!(output, "{}", privkey.expose_secret())
    })() {
        error!("Failed to write to output: {}", e);
    }
}
