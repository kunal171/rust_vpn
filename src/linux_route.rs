//! Discovers the existing Linux route to the VPN transport peer.
//!
//! Discovery must happen before full-tunnel routes are installed; otherwise
//! Linux could report `rvpn0` as the route to the VPN server itself.

use std::{error::Error, fmt, io, net::Ipv4Addr, process::Command};

/// Physical path that must continue carrying encrypted VPN datagrams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalRoute {
    gateway: Option<Ipv4Addr>,
    interface: String,
}

impl PhysicalRoute {
    /// Returns the gateway when the peer is not directly connected.
    pub const fn gateway(&self) -> Option<Ipv4Addr> {
        self.gateway
    }

    /// Returns the physical interface selected by Linux.
    pub fn interface(&self) -> &str {
        &self.interface
    }
}

/// Failure while querying or parsing the Linux routing table.
#[derive(Debug)]
pub enum LinuxRouteError {
    /// Running the `ip` command failed.
    Io(io::Error),

    /// Linux could not find a usable route.
    CommandFailed(String),

    /// The output did not contain a device.
    MissingInterface,

    /// The value following `via` was not an IPv4 address.
    InvalidGateway(String),
}

impl fmt::Display for LinuxRouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "route lookup failed: {error}"),
            Self::CommandFailed(message) => {
                write!(formatter, "ip route get failed: {message}")
            }
            Self::MissingInterface => {
                formatter.write_str("route lookup did not return an interface")
            }
            Self::InvalidGateway(value) => {
                write!(formatter, "route lookup returned invalid gateway {value:?}")
            }
        }
    }
}

impl Error for LinuxRouteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for LinuxRouteError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Parses one line produced by `ip -4 route get`.
pub fn parse_route_get(output: &str) -> Result<PhysicalRoute, LinuxRouteError> {
    let mut gateway = None;
    let mut interface = None;
    let mut tokens = output.split_whitespace();

    while let Some(token) = tokens.next() {
        match token {
            "via" => {
                let value = tokens
                    .next()
                    .ok_or_else(|| LinuxRouteError::InvalidGateway(String::new()))?;

                gateway = Some(
                    value
                        .parse()
                        .map_err(|_| LinuxRouteError::InvalidGateway(value.to_owned()))?,
                );
            }

            "dev" => {
                interface = tokens.next().map(str::to_owned);
            }

            _ => {}
        }
    }

    let interface = interface.ok_or(LinuxRouteError::MissingInterface)?;

    Ok(PhysicalRoute { gateway, interface })
}

/// Asks Linux which physical path currently reaches the VPN peer.
pub fn discover_physical_route(peer: Ipv4Addr) -> Result<PhysicalRoute, LinuxRouteError> {
    let output = Command::new("ip")
        .args(["-4", "route", "get"])
        .arg(peer.to_string())
        .output()?;

    if !output.status.success() {
        return Err(LinuxRouteError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }

    parse_route_get(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(test)]
mod tests {
    use super::{LinuxRouteError, parse_route_get};
    use std::net::Ipv4Addr;

    #[test]
    fn parses_a_route_through_a_gateway() {
        let route =
            parse_route_get("203.0.113.10 via 192.168.1.1 dev wlan0 src 192.168.1.20").unwrap();

        assert_eq!(route.gateway(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(route.interface(), "wlan0");
    }

    #[test]
    fn parses_a_directly_connected_route() {
        let route = parse_route_get("10.200.3.2 dev rvpnr-c src 10.200.3.1").unwrap();

        assert_eq!(route.gateway(), None);
        assert_eq!(route.interface(), "rvpnr-c");
    }

    #[test]
    fn rejects_output_without_an_interface() {
        let result = parse_route_get("203.0.113.10 via 192.168.1.1");

        assert!(matches!(result, Err(LinuxRouteError::MissingInterface)));
    }

    #[test]
    fn rejects_an_invalid_gateway() {
        let result = parse_route_get("203.0.113.10 via invalid dev wlan0");

        assert!(matches!(result, Err(LinuxRouteError::InvalidGateway(_))));
    }
}
