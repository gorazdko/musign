use clap::{ArgGroup, Clap, ValueHint};
use std::path::PathBuf;
use std::str::FromStr;
extern crate hex;
extern crate secp256k1;
use secp256k1::bitcoin_hashes::sha256;

//use secp256k1::rand::rngs::OsRng;
use secp256k1::{schnorrsig, Message, PublicKey, Secp256k1, SecretKey, Signature};

#[derive(Clap, Debug, PartialEq)]
enum SigType {
    ECDSA,
    Schnorr,
}

fn generate_schnorr_keypair(seed: String) -> (schnorrsig::KeyPair, schnorrsig::PublicKey) {
    let s = Secp256k1::new();

    let keypair = schnorrsig::KeyPair::from_seckey_str(&s, &seed).unwrap();

    let pubkey = schnorrsig::PublicKey::from_keypair(&s, &keypair);
    (keypair, pubkey)
}

fn sign_schnorr(seckey: String, msg: String) -> schnorrsig::Signature {
    let s = Secp256k1::new();
    let keypair = schnorrsig::KeyPair::from_seckey_str(&s, &seckey).unwrap();
    let pubkey = schnorrsig::PublicKey::from_keypair(&s, &keypair);

    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    let sig = s.schnorrsig_sign(&message, &keypair);

    assert!(s.schnorrsig_verify(&sig, &message, &pubkey).is_ok());

    sig
}

fn generate_keypair(seed: Vec<u8>) -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&seed).expect("seed should be 32 bytes (64 characters)");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    (secret_key, public_key)
}

fn sign(seckey: String, msg: String) -> Signature {
    let seckey =
        SecretKey::from_str(&seckey).expect("Private key must be 64 chars long hex string");

    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    let secp = Secp256k1::new();
    let sig = secp.sign(&message, &seckey);
    let public_key = PublicKey::from_secret_key(&secp, &seckey);
    assert!(secp.verify(&message, &sig, &public_key).is_ok());

    sig
}

fn verify(signature: String, msg: String, pubkey: String, _sig_type: SigType) -> bool {
    let pubkey = PublicKey::from_str(&pubkey).unwrap();
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
pub struct CmdSign {
    /// Path to private key (Not implemented)
    #[clap(parse(from_os_str), value_hint = ValueHint::AnyPath, short, long, group="seck")]
    seckey_file: Option<PathBuf>,
    /// Private key string in hex
    #[clap(long, short = 't', group = "seck")]
    seckey: Option<String>,
    /// Message to sign.
    #[clap(required = true)]
    msg: String,
    /// Signature type
    #[clap(arg_enum, default_value = "ecdsa")]
    sig_type: SigType,
}

#[derive(Debug, Clap)]
#[clap(group = ArgGroup::new("msg").required(true))]
pub struct CmdVerify {
    /// Signature as hex string
    #[clap(required = true)]
    signature: String,
    /// Signature as string
    #[clap(group = "msg", required = true)]
    message: String,
    /// Public key in hey string
    #[clap(required = true)]
    pubkey: String,
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
    Sign(CmdSign),

    /// Verify
    Verify(CmdVerify),
}

fn main() {
    let matches = Opt::parse();

    println!("{:?}", matches); // TODO: enclose under --verbose

    match matches {
        Opt::Generate { seed, sig_type } => {
            let seed_bytes = hex::decode(seed.clone()).expect("Decoding seed failed");

            match sig_type {
                SigType::ECDSA => {
                    let (_, pubkey) = generate_keypair(seed_bytes);
                    println!("public key: {:?}", pubkey.to_string());
                }
                SigType::Schnorr => {
                    let (_, pubkey) = generate_schnorr_keypair(seed);
                    println!("public key: {:?}", pubkey.to_string());
                }
            };
        }
        Opt::Sign(cmd) => {
            match cmd.sig_type {
                SigType::ECDSA => {
                    let sig = sign(cmd.seckey.expect("error private key string"), cmd.msg);
                    println!("{:?}", sig.to_string());
                }
                SigType::Schnorr => {
                    let sig = sign_schnorr(cmd.seckey.expect("error private key string"), cmd.msg);
                    println!("{:?}", sig.to_string());
                }
            };
        }
        Opt::Verify(cmd) => {
            let res = verify(cmd.signature, cmd.message, cmd.pubkey, cmd.sig_type);
            if res {
                println!("True");
            } else {
                println!("False");
            }
        } //_ => println!("dd"),
    };
}
