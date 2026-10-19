//! Installs and removes Linux routes required by an IPv4 full tunnel.
//!
//! The VPN peer bypass is installed before the split-default routes so the
//! encrypted UDP transport cannot accidentally enter its own tunnel.

use crate::{
    full_tunnel::FullTunnelPlan,
    linux_route::{LinuxRouteError, PhysicalRoute},
};
use std::{net::Ipv4Addr, process::Command};

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteSpec {
    destination: String,
    gateway: Option<Ipv4Addr>,
    interface: String,
}

impl RouteSpec {
    fn arguments(&self, action: &str) -> Vec<String> {
        let mut arguments = vec![
            "-4".to_owned(),
            "route".to_owned(),
            action.to_owned(),
            self.destination.clone(),
        ];

        if let Some(gateway) = self.gateway {
            arguments.push("via".to_owned());
            arguments.push(gateway.to_string());
        }

        arguments.push("dev".to_owned());
        arguments.push(self.interface.clone());

        arguments
    }
}

fn route_specs(
    plan: &FullTunnelPlan,
    physical_route: &PhysicalRoute,
    tunnel_interface: &str,
) -> Vec<RouteSpec> {
    let mut routes = vec![RouteSpec {
        destination: format!("{}/32", plan.peer_bypass()),
        gateway: physical_route.gateway(),
        interface: physical_route.interface().to_owned(),
    }];

    routes.extend(plan.tunnel_routes().iter().map(|route| RouteSpec {
        destination: route.to_string(),
        gateway: None,
        interface: tunnel_interface.to_owned(),
    }));

    routes
}

fn run_route_command(action: &str, route: &RouteSpec) -> Result<(), LinuxRouteError> {
    let arguments = route.arguments(action);
    let output = Command::new("ip").args(&arguments).output()?;

    if !output.status.success() {
        return Err(LinuxRouteError::CommandFailed(format!(
            "ip {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim(),
        )));
    }

    Ok(())
}

fn apply_with<F>(routes: Vec<RouteSpec>, mut execute: F) -> Result<Vec<RouteSpec>, LinuxRouteError>
where
    F: FnMut(&str, &RouteSpec) -> Result<(), LinuxRouteError>,
{
    let mut installed = Vec::new();

    for route in routes {
        if let Err(error) = execute("add", &route) {
            for installed_route in installed.iter().rev() {
                let _ = execute("del", installed_route);
            }

            return Err(error);
        }

        installed.push(route);
    }

    Ok(installed)
}

fn remove_with<F>(routes: &mut Vec<RouteSpec>, mut execute: F) -> Result<(), LinuxRouteError>
where
    F: FnMut(&str, &RouteSpec) -> Result<(), LinuxRouteError>,
{
    let mut failed_routes = Vec::new();
    let mut first_error = None;

    while let Some(route) = routes.pop() {
        if let Err(error) = execute("del", &route) {
            if first_error.is_none() {
                first_error = Some(error);
            }

            failed_routes.push(route);
        }
    }

    // Restore installation order so another cleanup attempt still runs backward.
    failed_routes.reverse();
    *routes = failed_routes;

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Owns the Linux routes installed for an active full-tunnel connection.
#[derive(Debug)]
pub struct InstalledFullTunnelRoutes {
    routes: Vec<RouteSpec>,
}

impl InstalledFullTunnelRoutes {
    /// Installs the peer bypass followed by both split-default routes.
    pub fn install(
        plan: &FullTunnelPlan,
        physical_route: &PhysicalRoute,
        tunnel_interface: &str,
    ) -> Result<Self, LinuxRouteError> {
        let routes = route_specs(plan, physical_route, tunnel_interface);
        let routes = apply_with(routes, run_route_command)?;

        Ok(Self { routes })
    }

    /// Removes installed routes in reverse installation order.
    pub fn remove(&mut self) -> Result<(), LinuxRouteError> {
        remove_with(&mut self.routes, run_route_command)
    }
}

impl Drop for InstalledFullTunnelRoutes {
    fn drop(&mut self) {
        let _ = remove_with(&mut self.routes, run_route_command);
    }
}

#[cfg(test)]
mod tests {
    use super::{RouteSpec, apply_with, remove_with};
    use crate::linux_route::LinuxRouteError;
    use std::net::Ipv4Addr;

    #[test]
    fn rolls_back_successful_routes_when_a_later_addition_fails() {
        let routes = vec![
            RouteSpec {
                destination: "203.0.113.10/32".to_owned(),
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "wlan0".to_owned(),
            },
            RouteSpec {
                destination: "0.0.0.0/1".to_owned(),
                gateway: None,
                interface: "rvpn0".to_owned(),
            },
            RouteSpec {
                destination: "128.0.0.0/1".to_owned(),
                gateway: None,
                interface: "rvpn0".to_owned(),
            },
        ];

        let mut calls = Vec::new();
        let mut additions = 0;

        let result = apply_with(routes, |action, route| {
            calls.push((action.to_owned(), route.destination.clone()));

            if action == "add" {
                additions += 1;

                if additions == 3 {
                    return Err(LinuxRouteError::CommandFailed(
                        "simulated failure".to_owned(),
                    ));
                }
            }

            Ok(())
        });

        assert!(result.is_err());
        assert_eq!(
            calls,
            vec![
                ("add".to_owned(), "203.0.113.10/32".to_owned()),
                ("add".to_owned(), "0.0.0.0/1".to_owned()),
                ("add".to_owned(), "128.0.0.0/1".to_owned()),
                ("del".to_owned(), "0.0.0.0/1".to_owned()),
                ("del".to_owned(), "203.0.113.10/32".to_owned()),
            ],
        );
    }

    #[test]
    fn removes_routes_in_reverse_installation_order() {
        let mut routes = vec![
            RouteSpec {
                destination: "203.0.113.10/32".to_owned(),
                gateway: None,
                interface: "eth0".to_owned(),
            },
            RouteSpec {
                destination: "0.0.0.0/1".to_owned(),
                gateway: None,
                interface: "rvpn0".to_owned(),
            },
        ];
        let mut deleted = Vec::new();

        remove_with(&mut routes, |action, route| {
            deleted.push((action.to_owned(), route.destination.clone()));
            Ok(())
        })
        .unwrap();

        assert!(routes.is_empty());
        assert_eq!(
            deleted,
            vec![
                ("del".to_owned(), "0.0.0.0/1".to_owned()),
                ("del".to_owned(), "203.0.113.10/32".to_owned()),
            ],
        );
    }
}
