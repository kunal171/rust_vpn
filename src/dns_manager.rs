//! Applies and removes per-link DNS policy through `systemd-resolved`.
//!
//! A route-only root domain (`~.`) tells the resolver that every DNS name
//! belongs to the VPN link. `resolvectl revert` restores the link to its
//! previous unmanaged state during shutdown or after partial setup failure.

use std::{error::Error, fmt, io, net::Ipv4Addr, process::Command};

/// Failure while configuring DNS for the VPN interface.
#[derive(Debug)]
pub enum DnsManagerError {
    /// Starting or waiting for `resolvectl` failed.
    Io(io::Error),

    /// A `resolvectl` operation returned an unsuccessful status.
    CommandFailed(String),

    /// Applying DNS failed and the rollback command also failed.
    RollbackFailed {
        /// Original configuration failure.
        apply: String,
        /// Failure returned while reverting the interface.
        rollback: String,
    },

    /// The supplied network-interface name was empty or contained whitespace.
    InvalidInterface,
}

impl fmt::Display for DnsManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "could not run resolvectl: {error}"),
            Self::CommandFailed(message) => write!(formatter, "resolvectl failed: {message}"),
            Self::RollbackFailed { apply, rollback } => write!(
                formatter,
                "DNS configuration failed ({apply}); rollback also failed ({rollback})"
            ),
            Self::InvalidInterface => {
                formatter.write_str("DNS interface name must not be empty or contain whitespace")
            }
        }
    }
}

impl Error for DnsManagerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for DnsManagerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedCommand {
    SetDns { interface: String, server: Ipv4Addr },
    SetDomain { interface: String },
    SetDefaultRoute { interface: String },
    Revert { interface: String },
}

impl ResolvedCommand {
    fn arguments(&self) -> Vec<String> {
        match self {
            Self::SetDns { interface, server } => {
                vec!["dns".to_owned(), interface.clone(), server.to_string()]
            }
            Self::SetDomain { interface } => {
                vec!["domain".to_owned(), interface.clone(), "~.".to_owned()]
            }
            Self::SetDefaultRoute { interface } => vec![
                "default-route".to_owned(),
                interface.clone(),
                "yes".to_owned(),
            ],
            Self::Revert { interface } => vec!["revert".to_owned(), interface.clone()],
        }
    }
}

fn validate_interface(interface: &str) -> Result<(), DnsManagerError> {
    if interface.is_empty() || interface.chars().any(char::is_whitespace) {
        return Err(DnsManagerError::InvalidInterface);
    }

    Ok(())
}

fn run_resolvectl(command: &ResolvedCommand) -> Result<(), DnsManagerError> {
    let arguments = command.arguments();
    let output = Command::new("resolvectl").args(&arguments).output()?;

    if !output.status.success() {
        return Err(DnsManagerError::CommandFailed(format!(
            "resolvectl {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim(),
        )));
    }

    Ok(())
}

fn revert_command(interface: &str) -> ResolvedCommand {
    ResolvedCommand::Revert {
        interface: interface.to_owned(),
    }
}

fn apply_with<F>(interface: &str, server: Ipv4Addr, mut execute: F) -> Result<(), DnsManagerError>
where
    F: FnMut(&ResolvedCommand) -> Result<(), DnsManagerError>,
{
    validate_interface(interface)?;

    let commands = [
        ResolvedCommand::SetDns {
            interface: interface.to_owned(),
            server,
        },
        ResolvedCommand::SetDomain {
            interface: interface.to_owned(),
        },
        ResolvedCommand::SetDefaultRoute {
            interface: interface.to_owned(),
        },
    ];

    for command in &commands {
        if let Err(apply_error) = execute(command) {
            if let Err(rollback_error) = execute(&revert_command(interface)) {
                return Err(DnsManagerError::RollbackFailed {
                    apply: apply_error.to_string(),
                    rollback: rollback_error.to_string(),
                });
            }

            return Err(apply_error);
        }
    }

    Ok(())
}

fn remove_with<F>(interface: &str, mut execute: F) -> Result<(), DnsManagerError>
where
    F: FnMut(&ResolvedCommand) -> Result<(), DnsManagerError>,
{
    execute(&revert_command(interface))
}

/// Owns the per-link DNS configuration installed for the VPN interface.
#[derive(Debug)]
pub struct InstalledDnsConfiguration {
    interface: String,
    active: bool,
}

impl InstalledDnsConfiguration {
    /// Routes every DNS name to `server` through `interface`.
    pub fn install(interface: &str, server: Ipv4Addr) -> Result<Self, DnsManagerError> {
        apply_with(interface, server, run_resolvectl)?;

        Ok(Self {
            interface: interface.to_owned(),
            active: true,
        })
    }

    /// Reverts all `systemd-resolved` settings owned by this guard.
    pub fn remove(&mut self) -> Result<(), DnsManagerError> {
        if !self.active {
            return Ok(());
        }

        remove_with(&self.interface, run_resolvectl)?;
        self.active = false;

        Ok(())
    }
}

impl Drop for InstalledDnsConfiguration {
    fn drop(&mut self) {
        if self.active {
            let _ = remove_with(&self.interface, run_resolvectl);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DnsManagerError, ResolvedCommand, apply_with, remove_with, validate_interface};
    use std::net::Ipv4Addr;

    const DNS_SERVER: Ipv4Addr = Ipv4Addr::new(10, 210, 0, 53);

    #[test]
    fn builds_the_expected_resolvectl_arguments() {
        let command = ResolvedCommand::SetDns {
            interface: "rvpn0".to_owned(),
            server: DNS_SERVER,
        };

        assert_eq!(command.arguments(), ["dns", "rvpn0", "10.210.0.53"]);

        let domain = ResolvedCommand::SetDomain {
            interface: "rvpn0".to_owned(),
        };

        assert_eq!(domain.arguments(), ["domain", "rvpn0", "~."]);
    }

    #[test]
    fn applies_dns_domain_and_default_route_in_order() {
        let mut calls = Vec::new();

        apply_with("rvpn0", DNS_SERVER, |command| {
            calls.push(command.clone());
            Ok(())
        })
        .unwrap();

        assert!(matches!(calls[0], ResolvedCommand::SetDns { .. }));
        assert!(matches!(calls[1], ResolvedCommand::SetDomain { .. }));
        assert!(matches!(calls[2], ResolvedCommand::SetDefaultRoute { .. }));
    }

    #[test]
    fn reverts_after_partial_configuration_failure() {
        let mut calls = Vec::new();

        let result = apply_with("rvpn0", DNS_SERVER, |command| {
            calls.push(command.clone());

            if matches!(command, ResolvedCommand::SetDomain { .. }) {
                return Err(DnsManagerError::CommandFailed(
                    "simulated domain failure".to_owned(),
                ));
            }

            Ok(())
        });

        assert!(matches!(result, Err(DnsManagerError::CommandFailed(_))));
        assert!(matches!(calls.last(), Some(ResolvedCommand::Revert { .. })));
    }

    #[test]
    fn reports_when_apply_and_rollback_both_fail() {
        let result = apply_with("rvpn0", DNS_SERVER, |command| match command {
            ResolvedCommand::SetDns { .. } => Err(DnsManagerError::CommandFailed(
                "simulated apply failure".to_owned(),
            )),
            ResolvedCommand::Revert { .. } => Err(DnsManagerError::CommandFailed(
                "simulated rollback failure".to_owned(),
            )),
            _ => Ok(()),
        });

        assert!(matches!(
            result,
            Err(DnsManagerError::RollbackFailed { .. })
        ));
    }

    #[test]
    fn removal_reverts_the_interface() {
        let mut calls = Vec::new();

        remove_with("rvpn0", |command| {
            calls.push(command.clone());
            Ok(())
        })
        .unwrap();

        assert_eq!(
            calls,
            [ResolvedCommand::Revert {
                interface: "rvpn0".to_owned(),
            }]
        );
    }

    #[test]
    fn rejects_an_invalid_interface_name() {
        assert!(matches!(
            validate_interface(""),
            Err(DnsManagerError::InvalidInterface)
        ));
        assert!(matches!(
            validate_interface("rvpn 0"),
            Err(DnsManagerError::InvalidInterface)
        ));
    }
}
