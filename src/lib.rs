#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppRole {
    Client,
    Server,
}

impl AppRole {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AppRole;

    #[test]
    fn returns_expected_role_labels() {
        assert_eq!(AppRole::Client.label(), "client");
        assert_eq!(AppRole::Server.label(), "server");
    }
}
