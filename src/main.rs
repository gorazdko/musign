use clap::{Clap, ValueHint};
use std::path::PathBuf;

#[derive(Clap, Debug, PartialEq)]
enum Signature {
    ECDSA,
    Schnorr,
}

#[derive(Clap, Debug)]
#[clap(name = "musig-cli")]
/// Generate secp256k1 keys, sign and verify messages with ECDSA and Schnorr
enum Opt {
    /// Generate a keypair
    Generate {
        /// Purpose
        #[clap(arg_enum, default_value = "ecdsa")]
        sig_type: Signature,
    },

    /// Sign
    Sign {
        /// Public key file
        #[clap(parse(from_os_str), value_hint = ValueHint::AnyPath, short)]
        pubkey_file: Option<PathBuf>,
        /// Public key string in hex
        #[clap(conflicts_with = "pubkey-file", short = 's')]
        pubkey_string: Option<String>,
        /// File to sign
        #[clap(name = "FILE", parse(from_os_str), value_hint = ValueHint::AnyPath)]
        file: PathBuf,
        /// Signature type
        #[clap(arg_enum, default_value = "ecdsa")]
        sig_type: Signature,
    },
    /// Verify
    Verify {
        /// Signature file
        #[clap(parse(from_os_str), value_hint = ValueHint::AnyPath, short)]
        signature_file: Option<PathBuf>,
        /// Signature as string
        #[clap(conflicts_with = "signature-file", short = 'g')]
        signature_string: Option<String>,
        /// Signature file
        #[clap(parse(from_os_str), value_hint = ValueHint::AnyPath, short)]
        message_file: Option<PathBuf>,
        /// Signature as string
        #[clap(conflicts_with = "message-file", short = 'a')]
        message_string: Option<String>,
    },
}

fn main() {
    let matches = Opt::parse();

    println!("{:?}", matches);

    /*
        match matches {
            Opt::Sign {
                dry_run,
                all,
                repository,
            } => {
                // here is where you call a function e.g. sign
                println!("{:?} {:?} {:?}", dry_run, all, repository)
            }
            Opt::Verify {
                interactive,
                all,
                files,
            } => {
                // here is where you call a function e.g. sign
                println!("{:?} {:?} {:?}", interactive, all, files)
            }
        };
    */
}
