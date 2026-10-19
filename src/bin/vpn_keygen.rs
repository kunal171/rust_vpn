//! Provisions one long-term Ed25519 identity for the educational VPN.

use rust_vpn::identity::IdentityKeyPair;
use std::{
    env,
    error::Error,
    fs::OpenOptions,
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use zeroize::Zeroize;

const USAGE: &str = "usage: vpn_keygen <private-key-file> <public-key-file>";

/// Returns one required path argument with a useful command-line error.
fn required_argument(
    arguments: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, Box<dyn Error>> {
    arguments
        .next()
        .ok_or_else(|| format!("missing {name}\n{USAGE}").into())
}

/// Creates rather than truncates a key file, with an explicit Unix mode.
fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;

    file.write_all(bytes)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    let private_path = required_argument(&mut arguments, "private-key-file")?;
    let public_path = required_argument(&mut arguments, "public-key-file")?;

    if arguments.next().is_some() {
        return Err(format!("too many arguments\n{USAGE}").into());
    }

    let identity = IdentityKeyPair::generate()?;
    let mut private_key = identity.secret_key_bytes();

    // Erase the temporary seed even when creating or writing the file fails.
    let private_result = write_new_file(Path::new(&private_path), &private_key, 0o600);
    private_key.zeroize();
    private_result?;

    write_new_file(Path::new(&public_path), &identity.public_key(), 0o644)?;

    println!("Created private identity file {private_path} with mode 0600");
    println!("Created public identity file {public_path}");

    Ok(())
}
