use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolDomain {
    Proc,
    Hw,
    Shell,
    Pe,
}

impl ToolDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proc => "proc",
            Self::Hw => "hw",
            Self::Shell => "shell",
            Self::Pe => "pe",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCatalogEntry {
    pub tool_id: &'static str,
    pub domain: ToolDomain,
    pub display_name: &'static str,
    pub cli_subcommand: &'static str,
    pub read_only: bool,
}
