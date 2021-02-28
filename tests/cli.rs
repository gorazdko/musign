use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*; // Used for writing assertions
use std::process::Command; // Run programs

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
