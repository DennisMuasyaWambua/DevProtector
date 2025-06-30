use reqwest;
use serde_json::json;
use std::fs;
use uuid::Uuid;
use std::env;
use crate::error::AppError;
use tracing::{info, error};

// Onramping services
const SWYPT_PAYMENT_URL: &str = "https://api.swyptpay.com/v1/onramp";
const ELEMENT_PAYMENT_URL: &str = "https://api.elementpay.com/v1/purchase";
const SMART_CONTRACT_URL: &str = "https://api.your-blockchain-provider.com/v1/contracts/project-creation";

// Fixed amount in KSH
const PROTECTION_FEE_KSH: f32 = 400.0;

pub async fn run(phone: String, amount: f32) -> Result<(), AppError> {
    let current_dir = env::current_dir().map_err(|e| {
        AppError::Config(format!("Failed to get current directory: {}", e))
    })?;
    
    let project_name = current_dir.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown_project")
        .to_string();
    
    info!("🚀 Initializing protection for project: {}", project_name);
    info!("💰 Protection fee: KSH {}", PROTECTION_FEE_KSH);
    
    let project_uuid = Uuid::new_v4().to_string();
    
    // Step 1: Create project on smart contract
    info!("📝 Creating project on blockchain...");
    let _smart_contract_result = create_project_on_blockchain(&project_uuid, &project_name, &phone, amount).await?;
    
    // Step 2: Request KSH 400 payment via onramping service
    info!("💳 Requesting payment via onramping service...");
    let payment_result = request_onramp_payment(&phone, &project_uuid).await?;
    
    if payment_result.success {
        info!("✅ Payment request successful. Please complete payment to proceed.");
        save_project_config(&project_uuid, &phone, amount, &project_name)?;
        
        // Step 3: Inject monitoring code based on detected framework
        inject_framework_monitoring(&project_uuid).await?;
        
        info!("🔐 Project protection initialized successfully!");
        info!("📱 Complete payment of KSH {} to activate protection", PROTECTION_FEE_KSH);
        Ok(())
    } else {
        error!("❌ Payment request failed: {}", payment_result.error);
        Err(AppError::Payment(format!("Payment request failed: {}", payment_result.error)))
    }
}

fn save_project_config(uuid: &str, phone: &str, amount: f32, name: &str) -> Result<(), AppError> {
    let current_dir = env::current_dir().map_err(|e| {
        AppError::Config(format!("Failed to get current directory: {}", e))
    })?;
    
    let path = current_dir.to_str().unwrap_or(".");
    
    let config = format!(
        r#"[project]
uuid = "{}"
phone = "{}"
amount = {}
name = "{}"
path = "{}"
"#,
        uuid, phone, amount, name, path
    );
    
    fs::write(".ipproject", config).map_err(|e| {
        AppError::Config(format!("Failed to save project config: {}", e))
    })?;
    
    Ok(())
}

#[derive(Debug)]
struct SmartContractResult {
    success: bool,
    contract_address: String,
    error: String,
}

#[derive(Debug)]
struct PaymentResult {
    success: bool,
    payment_id: String,
    error: String,
}

async fn create_project_on_blockchain(
    uuid: &str,
    project_name: &str, 
    phone: &str,
    amount: f32
) -> Result<SmartContractResult, AppError> {
    let payload = json!({
        "project_id": uuid,
        "project_name": project_name,
        "owner_phone": phone,
        "protection_amount": amount,
        "required_payment": PROTECTION_FEE_KSH,
        "encryption_status": false
    });

    let client = reqwest::Client::new();
    let response = client
        .post(SMART_CONTRACT_URL)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| AppError::Reqwest(e))?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await
            .map_err(|e| AppError::Payment(format!("Failed to parse response: {}", e)))?;
        
        Ok(SmartContractResult {
            success: true,
            contract_address: result["contract_address"].as_str().unwrap_or("").to_string(),
            error: String::new(),
        })
    } else {
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        Ok(SmartContractResult {
            success: false,
            contract_address: String::new(),
            error: error_text,
        })
    }
}

async fn request_onramp_payment(phone: &str, uuid: &str) -> Result<PaymentResult, AppError> {
    // Try Swypt first, fallback to Element Pay
    match try_swypt_payment(phone, uuid).await {
        Ok(result) if result.success => Ok(result),
        _ => try_element_payment(phone, uuid).await,
    }
}

async fn try_swypt_payment(phone: &str, uuid: &str) -> Result<PaymentResult, AppError> {
    let payload = json!({
        "amount": PROTECTION_FEE_KSH,
        "currency": "KES",
        "phone_number": phone,
        "reference": uuid,
        "description": "DevProtector IP Protection Fee",
        "webhook_url": format!("https://api.your-domain.com/webhook/swypt/{}", uuid)
    });

    let client = reqwest::Client::new();
    let response = client
        .post(SWYPT_PAYMENT_URL)
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer YOUR_SWYPT_API_KEY")
        .json(&payload)
        .send()
        .await
        .map_err(|e| AppError::Reqwest(e))?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await
            .map_err(|e| AppError::Payment(format!("Failed to parse Swypt response: {}", e)))?;
        
        info!("✅ Swypt payment request initiated");
        Ok(PaymentResult {
            success: true,
            payment_id: result["payment_id"].as_str().unwrap_or("").to_string(),
            error: String::new(),
        })
    } else {
        let error_text = response.text().await.unwrap_or_else(|_| "Swypt payment failed".to_string());
        Ok(PaymentResult {
            success: false,
            payment_id: String::new(),
            error: error_text,
        })
    }
}

async fn try_element_payment(phone: &str, uuid: &str) -> Result<PaymentResult, AppError> {
    let payload = json!({
        "amount": PROTECTION_FEE_KSH,
        "currency": "KES",
        "customer_phone": phone,
        "order_id": uuid,
        "description": "DevProtector IP Protection Service",
        "callback_url": format!("https://api.your-domain.com/webhook/element/{}", uuid)
    });

    let client = reqwest::Client::new();
    let response = client
        .post(ELEMENT_PAYMENT_URL)
        .header("Content-Type", "application/json")
        .header("X-API-Key", "YOUR_ELEMENT_API_KEY")
        .json(&payload)
        .send()
        .await
        .map_err(|e| AppError::Reqwest(e))?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await
            .map_err(|e| AppError::Payment(format!("Failed to parse Element response: {}", e)))?;
        
        info!("✅ Element Pay payment request initiated");
        Ok(PaymentResult {
            success: true,
            payment_id: result["transaction_id"].as_str().unwrap_or("").to_string(),
            error: String::new(),
        })
    } else {
        let error_text = response.text().await.unwrap_or_else(|_| "Element payment failed".to_string());
        Ok(PaymentResult {
            success: false,
            payment_id: String::new(),
            error: error_text,
        })
    }
}

async fn inject_framework_monitoring(uuid: &str) -> Result<(), AppError> {
    // Detect framework and inject appropriate monitoring code
    let framework = detect_project_framework().await?;
    
    match framework.as_str() {
        "nodejs" => inject_nodejs_monitoring(uuid).await,
        "python" => inject_python_monitoring(uuid).await,
        "rust" => inject_rust_monitoring(uuid).await,
        "react" | "vue" | "angular" => inject_frontend_monitoring(uuid).await,
        _ => {
            info!("⚠️ Framework not detected or supported. Generic protection applied.");
            Ok(())
        }
    }
}

async fn detect_project_framework() -> Result<String, AppError> {
    let current_dir = env::current_dir().map_err(|e| {
        AppError::Config(format!("Failed to get current directory: {}", e))
    })?;
    
    // Check for Node.js
    if current_dir.join("package.json").exists() {
        return Ok("nodejs".to_string());
    }
    
    // Check for Python
    if current_dir.join("requirements.txt").exists() || 
       current_dir.join("pyproject.toml").exists() ||
       current_dir.join("Pipfile").exists() {
        return Ok("python".to_string());
    }
    
    // Check for Rust
    if current_dir.join("Cargo.toml").exists() {
        return Ok("rust".to_string());
    }
    
    // Check for frontend frameworks
    if let Ok(package_content) = fs::read_to_string(current_dir.join("package.json")) {
        if package_content.contains("react") {
            return Ok("react".to_string());
        } else if package_content.contains("vue") {
            return Ok("vue".to_string());
        } else if package_content.contains("@angular") {
            return Ok("angular".to_string());
        }
    }
    
    Ok("unknown".to_string())
}

async fn inject_nodejs_monitoring(uuid: &str) -> Result<(), AppError> {
    let monitoring_code = format!(
        r#"
// DevProtector IP Protection Monitoring (Auto-generated)
const DEVPROTECTOR_PROJECT_ID = '{}';
const DEVPROTECTOR_CHECK_INTERVAL = 60000; // 1 minute
const axios = require('axios');

async function checkDevProtectorStatus() {{
    try {{
        const response = await axios.get(
            `https://api.your-blockchain-provider.com/v1/contracts/project-status/${{DEVPROTECTOR_PROJECT_ID}}`
        );
        
        if (response.data.encryption_status === true) {{
            console.log('🔐 DevProtector: Project protection activated - encrypting codebase...');
            // Trigger encryption
            require('child_process').exec('npx devprotector encrypt', (error) => {{
                if (error) console.error('DevProtector encryption failed:', error);
            }});
        }}
    }} catch (error) {{
        console.error('DevProtector status check failed:', error.message);
    }}
}}

// Start monitoring
checkDevProtectorStatus();
setInterval(checkDevProtectorStatus, DEVPROTECTOR_CHECK_INTERVAL);

module.exports = {{ checkDevProtectorStatus }};
"#,
        uuid
    );

    // Find package.json and add monitoring script
    let package_path = env::current_dir()?.join("package.json");
    if package_path.exists() {
        // Create monitoring file
        fs::write("devprotector-monitor.js", monitoring_code)
            .map_err(|e| AppError::Injection(format!("Failed to create monitoring file: {}", e)))?;
        
        info!("✅ Node.js monitoring code injected");
    }
    
    Ok(())
}

async fn inject_python_monitoring(uuid: &str) -> Result<(), AppError> {
    let monitoring_code = format!(
        r#"
# DevProtector IP Protection Monitoring (Auto-generated)
import os
import sys
import time
import threading
import requests
import subprocess

DEVPROTECTOR_PROJECT_ID = '{}'
DEVPROTECTOR_CHECK_INTERVAL = 60  # 1 minute

def check_devprotector_status():
    """Check encryption status from smart contract"""
    try:
        response = requests.get(
            f'https://api.your-blockchain-provider.com/v1/contracts/project-status/{{DEVPROTECTOR_PROJECT_ID}}'
        )
        data = response.json()
        
        if data.get('encryption_status') is True:
            print('🔐 DevProtector: Project protection activated - encrypting codebase...')
            # Trigger encryption
            subprocess.run([sys.executable, '-m', 'devprotector', 'encrypt'], check=False)
    except Exception as e:
        print(f'DevProtector status check failed: {{e}}')

def start_devprotector_monitoring():
    """Start monitoring thread"""
    def monitor_loop():
        while True:
            check_devprotector_status()
            time.sleep(DEVPROTECTOR_CHECK_INTERVAL)
    
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()

# Auto-start monitoring
start_devprotector_monitoring()
"#,
        uuid
    );

    // Create monitoring file
    fs::write("devprotector_monitor.py", monitoring_code)
        .map_err(|e| AppError::Injection(format!("Failed to create Python monitoring file: {}", e)))?;
    
    info!("✅ Python monitoring code injected");
    Ok(())
}

async fn inject_rust_monitoring(uuid: &str) -> Result<(), AppError> {
    let monitoring_code = format!(
        r#"
// DevProtector IP Protection Monitoring (Auto-generated)
use std::{{thread, time::Duration}};
use tokio::time::interval;

const DEVPROTECTOR_PROJECT_ID: &str = "{}";
const DEVPROTECTOR_CHECK_INTERVAL: u64 = 60; // 1 minute

#[tokio::main]
async fn main() {{
    let mut interval = interval(Duration::from_secs(DEVPROTECTOR_CHECK_INTERVAL));
    
    loop {{
        interval.tick().await;
        check_devprotector_status().await;
    }}
}}

async fn check_devprotector_status() {{
    match reqwest::get(&format!(
        "https://api.your-blockchain-provider.com/v1/contracts/project-status/{{}}",
        DEVPROTECTOR_PROJECT_ID
    )).await {{
        Ok(response) => {{
            if let Ok(data) = response.json::<serde_json::Value>().await {{
                if data.get("encryption_status").and_then(|v| v.as_bool()).unwrap_or(false) {{
                    println!("🔐 DevProtector: Project protection activated - encrypting codebase...");
                    
                    // Trigger encryption
                    let _ = std::process::Command::new("cargo")
                        .args(&["run", "--bin", "devprotector", "encrypt"])
                        .output();
                }}
            }}
        }}
        Err(e) => eprintln!("DevProtector status check failed: {{}}", e),
    }}
}}
"#,
        uuid
    );

    // Create monitoring binary
    fs::write("src/bin/devprotector_monitor.rs", monitoring_code)
        .map_err(|e| AppError::Injection(format!("Failed to create Rust monitoring file: {}", e)))?;
    
    info!("✅ Rust monitoring code injected");
    Ok(())
}

async fn inject_frontend_monitoring(uuid: &str) -> Result<(), AppError> {
    let monitoring_code = format!(
        r#"
// DevProtector IP Protection Monitoring (Auto-generated)
const DEVPROTECTOR_PROJECT_ID = '{}';
const DEVPROTECTOR_CHECK_INTERVAL = 60000; // 1 minute

class DevProtectorMonitor {{
    constructor() {{
        this.startMonitoring();
    }}

    async checkStatus() {{
        try {{
            const response = await fetch(
                `https://api.your-blockchain-provider.com/v1/contracts/project-status/${{DEVPROTECTOR_PROJECT_ID}}`
            );
            const data = await response.json();
            
            if (data.encryption_status === true) {{
                console.log('🔐 DevProtector: Project protection activated');
                this.showPaymentWall();
            }}
        }} catch (error) {{
            console.error('DevProtector status check failed:', error);
        }}
    }}

    showPaymentWall() {{
        // Replace entire page with payment wall
        document.body.innerHTML = `
            <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                        display: flex; align-items: center; justify-content: center; 
                        font-family: Arial, sans-serif; z-index: 999999;">
                <div style="background: white; padding: 40px; border-radius: 10px; 
                           text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
                    <h1 style="color: #333; margin-bottom: 20px;">🔐 DevProtector</h1>
                    <p style="color: #666; margin-bottom: 30px;">
                        This application is protected by DevProtector.<br>
                        Payment required to access the application.
                    </p>
                    <button onclick="window.open('https://payment.your-domain.com/${{DEVPROTECTOR_PROJECT_ID}}', '_blank')"
                            style="background: #667eea; color: white; padding: 15px 30px; 
                                   border: none; border-radius: 5px; cursor: pointer; font-size: 16px;">
                        Complete Payment
                    </button>
                </div>
            </div>
        `;
    }}

    startMonitoring() {{
        this.checkStatus();
        setInterval(() => this.checkStatus(), DEVPROTECTOR_CHECK_INTERVAL);
    }}
}}

// Auto-start monitoring when DOM is ready
document.addEventListener('DOMContentLoaded', () => {{
    new DevProtectorMonitor();
}});

export default DevProtectorMonitor;
"#,
        uuid
    );

    // Create monitoring script
    fs::write("devprotector-monitor.js", monitoring_code)
        .map_err(|e| AppError::Injection(format!("Failed to create frontend monitoring file: {}", e)))?;
    
    info!("✅ Frontend monitoring code injected");
    Ok(())
}