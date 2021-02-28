use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*; // Used for writing assertions
use std::process::Command;
use std::str::FromStr; // Run programs

#[test]
fn help_subcommand() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("musig-cli")?;

    cmd.arg("sign").arg("-h");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("USAGE"));

    Ok(())
}

#[test]
fn generate_keypair() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("musig-cli")?;

    // Generate ECDSA keypair
    let seed = "7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b";
    let privkey = "7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b";
    let pubkey = "03dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59";

    cmd.arg("generate").arg(seed);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(pubkey))
        .stdout(predicate::str::contains(privkey));

    Ok(())
}

#[test]
fn sign_verify() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("musig-cli")?;

    let privkey = "e6dd32f8761625f105c39a39f19370b3521d845a12456d60ce44debd0a362641";
    let msg_data = "Hello world!";
    let sig = "3045022100a834a9596c3021524305faa75a83a545780260e059832128d9617f4479876613022036bc08f2aed098d1e598106ab1439d4bcdbed127db73072358a4ca21f3dbd4f2";

    cmd.arg("sign").arg(msg_data).arg("--seckey").arg(privkey);

    cmd.assert().success().stdout(predicate::str::contains(sig));

    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let seckey = SecretKey::from_str(privkey).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &seckey);

    println!("pubkey string {:?}", pubkey.to_string());

    let mut cmd = Command::cargo_bin("musig-cli")?;
    cmd.arg("verify")
        .arg(sig)
        .arg(msg_data)
        .arg(pubkey.to_string());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("True"));

    Ok(())
}
