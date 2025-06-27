use std::fs;
use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum Framework {
    Rust,
    NextJs,
    ReactNative,
    NodeJs,
    Unknown,
}

pub fn detect_framework(project_path: &str) -> Framework {
    // Check for Cargo.toml for Rust
    if Path::new(project_path).join("Cargo.toml").exists() {
        return Framework::Rust;
    }

    // Check for package.json for Node.js based frameworks
    if Path::new(project_path).join("package.json").exists() {
        let package_json_path = Path::new(project_path).join("package.json");
        if let Ok(content) = fs::read_to_string(&package_json_path) {
            if content.contains("next") {
                return Framework::NextJs;
            }
            if content.contains("react-native") {
                return Framework::ReactNative;
            }
            // Default to NodeJs if package.json exists
            return Framework::NodeJs;
        }
    }

    Framework::Unknown
}
