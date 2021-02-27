use clap::{Clap, ValueHint};
use std::path::PathBuf;
extern crate hex;
extern crate secp256k1;

//use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

#[derive(Clap, Debug, PartialEq)]
enum Signature {
    ECDSA,
    Schnorr,
}

fn generate_keypair(seed: Vec<u8>, _sig_type: Signature) -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&seed).expect("seed should be 32 bytes (64 characters)");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    (secret_key, public_key)
}

#[derive(Clap, Debug)]
#[clap(name = "musig-cli")]
/// Generate secp256k1 keys, sign and verify messages with ECDSA and Schnorr
enum Opt {
    /// Generate a keypair
    Generate {
        /// Seed in hex string
        seed: String,
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

    match matches {
        Opt::Generate { seed, sig_type } => {
            let seed = hex::decode(seed).expect("Decoding seed failed");
            let (seckey, pubkey) = generate_keypair(seed, sig_type);
            println!("private key: {:?}", seckey.to_string());
            println!("public key: {:?}", seckey.to_string());
        }
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
}
