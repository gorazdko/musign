use clap::{ArgGroup, Clap, ValueHint};
use std::path::PathBuf;
use std::str::FromStr;
extern crate hex;
extern crate secp256k1;
use secp256k1::bitcoin_hashes::sha256;

//use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature};

#[derive(Clap, Debug, PartialEq)]
enum SigType {
    ECDSA,
    Schnorr,
}

fn generate_keypair(seed: Vec<u8>, _sig_type: SigType) -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&seed).expect("seed should be 32 bytes (64 characters)");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    (secret_key, public_key)
}

fn sign(seckey: String, msg: String, _sig_type: SigType) -> bool {
    let seckey =
        SecretKey::from_str(&seckey).expect("Private key must be 64 chars long hex string");

    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    let secp = Secp256k1::new();
    let sig = secp.sign(&message, &seckey);
    let public_key = PublicKey::from_secret_key(&secp, &seckey);
    assert!(secp.verify(&message, &sig, &public_key).is_ok());

    true
}

fn verify(pubkey: String, msg: String, signature: String, _sig_type: SigType) -> bool {
    let pubkey = PublicKey::from_str(&pubkey).expect("Public key must be 65 chars long hex string");
    let sig = Signature::from_str(&signature).expect("Signature format incorrect");

    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    let secp = Secp256k1::new();

    if secp.verify(&message, &sig, &pubkey).is_ok() {
        true
    } else {
        false
    }
}

#[derive(Debug, Clap)]
#[clap(group = ArgGroup::new("seck").required(true))]
pub struct Sign2 {
    /// Public key file
    #[clap(parse(from_os_str), value_hint = ValueHint::AnyPath, short, long, group="seck")]
    seckey_file: Option<PathBuf>,
    /// Public key string in hex
    #[clap(long, short = 't', group = "seck")]
    seckey_string: Option<String>,
    /// File to sign
    #[clap(name = "FILE", parse(from_os_str), value_hint = ValueHint::AnyPath)]
    file: PathBuf,
    /// Message string to sign. Must be 32 bytes.
    #[clap(conflicts_with = "FILE", short = 'm')]
    msg_string: Option<String>,
    /// Signature type
    #[clap(arg_enum, default_value = "ecdsa")]
    sig_type: SigType,
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
        sig_type: SigType,
    },

    //#[clap(subcommand)]
    Command2(Sign2),

    //#[clap(group = ArgGroup::new("seck").required(false))]
    /// Sign
    Sign {
        /// Public key file
        #[clap(parse(from_os_str), value_hint = ValueHint::AnyPath, short, long, group="seck")]
        seckey_file: Option<PathBuf>,
        /// Public key string in hex
        #[clap(long, short = 't', group = "seck")]
        seckey_string: Option<String>,
        /// File to sign
        #[clap(name = "FILE", parse(from_os_str), value_hint = ValueHint::AnyPath)]
        file: PathBuf,
        /// Message string to sign. Must be 32 bytes.
        #[clap(conflicts_with = "FILE", short = 'm')]
        msg_string: Option<String>,
        /// Signature type
        #[clap(arg_enum, default_value = "ecdsa")]
        sig_type: SigType,
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
        /// Public key in hey string
        #[clap(short = 'p', required = true)]
        pubkey_string: String,
        #[clap(arg_enum, default_value = "ecdsa")]
        sig_type: SigType,
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
            println!("public key: {:?}", pubkey.to_string());
        }
        Opt::Sign {
            seckey_file: _,
            seckey_string,
            file: _,
            msg_string,
            sig_type,
        } => {
            let res = sign(
                seckey_string.expect("error private key string"),
                msg_string.expect("error: msg string"),
                sig_type,
            );

            if res {
                println!("OK");
            } else {
                println!("NOK");
            }
        }

        Opt::Verify {
            signature_file: _,
            signature_string,
            message_file: _,
            message_string,
            pubkey_string,
            sig_type,
        } => {
            verify(
                pubkey_string,
                message_string.expect("error: msg string"),
                signature_string.expect("sig string"),
                sig_type,
            );
        }
        _ => println!("dd"),
    };
}
