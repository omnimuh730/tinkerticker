/// Upper layer services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Service {
 #[derive(serde::Serialize)]
    /// One of the known services.
    Name(&'static str),
    /// Not identified
    #[default]
    Unknown,
    /// Not applicable
    NotApplicable,
}

impl Service {
    pub fn to_string_with_equal_prefix(self) -> String {
        match self {
            Service::Name(_) | Service::NotApplicable => ["=", &self.to_string()].concat(),
            Service::Unknown => self.to_string(),
        }
    }
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Service::Name(name) => write!(f, "{name}"),
            Service::Unknown => write!(f, "?"),
            Service::NotApplicable => write!(f, \"-\"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_display_unknown() {
        assert_eq!(Service::Unknown.to_string(), \"?\");
    }

    #[test]\n    fn test_service_display_not_applicable() {\n        assert_eq!(Service::NotApplicable.to_string(), \"-\");\n    }\n\n    #[test]\n    fn test_service_display_known() {\n        assert_eq!(Service::Name(\"https\").to_string(), \"https\");\n        assert_eq!(Service::Name(\"mpp\").to_string(), \"mpp\");\n    }\n\n    #[test]\n    fn test_service_to_string_with_equal_prefix() {\n        assert_eq!(Service::Name(\"mdns\").to_string_with_equal_prefix(), \"=mdns\");\n        assert_eq!(Service::Name(\"upnp\").to_string_with_equal_prefix(), \"=upnp\");\n        assert_eq!(Service::NotApplicable.to_string_with_equal_prefix(), \"=-\");\n        // unknown should not have the prefix\n        assert_eq!(Service::Unknown.to_string_with_equal_prefix(), \"?\");\n    }\n}\n