use base64::Engine;
use chrono::{DateTime, Utc};
use reqwest::{Client, Error as ReqwestError};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use uuid::Uuid;
use crate::error::AppError;
use tracing::info;
use crate::commands::detect::{detect_framework, Framework};



#[derive(Debug)]
pub enum MpesaError {
    RequestError(ReqwestError),
    EnvVarError(env::VarError),
    SerializationError(serde_json::Error),
}

impl From<ReqwestError> for MpesaError {
    fn from(error: ReqwestError) -> Self {
        MpesaError::RequestError(error)
    }
}

impl From<env::VarError> for MpesaError {
    fn from(error: env::VarError) -> Self {
        MpesaError::EnvVarError(error)
    }
}

impl From<serde_json::Error> for MpesaError {
    fn from(error: serde_json::Error) -> Self {
        MpesaError::SerializationError(error)
    }
}

impl From<MpesaError> for AppError {
    fn from(error: MpesaError) -> Self {
        match error {
            MpesaError::RequestError(e) => AppError::Reqwest(e),
            MpesaError::EnvVarError(e) => AppError::Config(format!("Environment variable error: {}", e)),
            MpesaError::SerializationError(e) => AppError::Json(e),
        }
    }
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: String,
}

#[derive(Serialize, Debug)]
struct StkPushRequest {
    #[serde(rename = "BusinessShortCode")]
    business_short_code: String,
    #[serde(rename = "Password")]
    password: String,
    #[serde(rename = "Timestamp")]
    timestamp: String,
    #[serde(rename = "TransactionType")]
    transaction_type: String,
    #[serde(rename = "Amount")]
    amount: u32,
    #[serde(rename = "PartyA")]
    party_a: String,
    #[serde(rename = "PartyB")]
    party_b: String,
    #[serde(rename = "PhoneNumber")]
    phone_number: String,
    #[serde(rename = "CallBackURL")]
    callback_url: String,
    #[serde(rename = "AccountReference")]
    account_reference: String,
    #[serde(rename = "TransactionDesc")]
    transaction_desc: String,
}

#[derive(Serialize)]
#[allow(dead_code)]
struct BalanceRequest {
    #[serde(rename = "Initiator")]
    initiator: String,
    #[serde(rename = "SecurityCredential")]
    security_credential: String,
    #[serde(rename = "CommandID")]
    command_id: String,
    #[serde(rename = "PartyA")]
    party_a: String,
    #[serde(rename = "IdentifierType")]
    identifier_type: String,
    #[serde(rename = "Remarks")]
    remarks: String,
    #[serde(rename = "QueueTimeOutURL")]
    queue_timeout_url: String,
    #[serde(rename = "ResultURL")]
    result_url: String,
}

pub struct MpesaC2bApi {
    consumer_key: String,
    consumer_secret: String,
    access_token: Option<String>,
    client: Client,
}

impl MpesaC2bApi {
    pub fn new(consumer_key: String, consumer_secret: String) -> Self {
        Self {
            consumer_key,
            consumer_secret,
            access_token: None,
            client: Client::new(),
        }
    }

    /// Generate access token
    pub async fn generate_access_token(&mut self) -> Result<String, MpesaError> {
        let auth_string = format!("{}:{}", self.consumer_key, self.consumer_secret);
        let auth_encoded = base64::engine::general_purpose::STANDARD.encode(auth_string);
        
        let oauth_url = env::var("OAUTH_URL").map_err(|e| {
            MpesaError::EnvVarError(e)
        })?;
        
        let response = self
            .client
            .get(&oauth_url)
            .header("Authorization", format!("Basic {}", auth_encoded))
            .send()
            .await?;

        let token_response: AccessTokenResponse = response.json().await?;
        self.access_token = Some(token_response.access_token.clone());
        println!("Access Token: {}", token_response.access_token);
        
        Ok(token_response.access_token)
    }

    /// Initiate a C2B STK push transaction
    pub async fn initiate_payment(
        &mut self,
        amount: u32,
        phone: &str,
        callback_url: &str,
    ) -> Result<serde_json::Value, MpesaError> {
        let token = self.generate_access_token().await?;
        
        let stk_push_url = env::var("STK_PUSH_URL").map_err(|_| MpesaError::EnvVarError(env::VarError::NotPresent))?;
        let short_code = env::var("MPESA_SHORT_CODE").map_err(|_| MpesaError::EnvVarError(env::VarError::NotPresent))?;
        let pass_key = env::var("C2B_PASS_KEY").map_err(|_| MpesaError::EnvVarError(env::VarError::NotPresent))?;
        
        // Generate timestamp
        let now: DateTime<Utc> = Utc::now();
        let timestamp = now.format("%Y%m%d%H%M%S").to_string();
        
        // Generate password
        let password_string = format!("{}{}{}", short_code, pass_key, timestamp);
        let password = base64::engine::general_purpose::STANDARD.encode(password_string);

        let request_body = StkPushRequest {
            business_short_code: short_code.clone(),
            password,
            timestamp,
            transaction_type: "CustomerPayBillOnline".to_string(),
            amount,
            party_a: phone.to_string(),
            party_b: short_code,
            phone_number: phone.to_string(),
            callback_url: callback_url.to_string(),
            account_reference: "CompanyXLTD".to_string(),
            transaction_desc: "Payment of X".to_string(),
        };

        println!("Request Body: {:?}", request_body);

        let response = self
            .client
            .post(&stk_push_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let response_data: serde_json::Value = response.json().await?;
        println!("Response Data: {:?}", response_data);
        Ok(response_data)
    }

    /// Check balance
    #[allow(dead_code)]
    pub async fn check_balance(&mut self) -> Result<serde_json::Value, MpesaError> {
        let token = self.generate_access_token().await?;
        
        let account_bal_url = env::var("ACCOUNT_BAL_URL").map_err(|_| MpesaError::EnvVarError(env::VarError::NotPresent))?;
        let initiator = env::var("MPESA_INITIATOR").map_err(|_| MpesaError::EnvVarError(env::VarError::NotPresent))?;
        let security_credential = env::var("MPESA_SECURITY_CREDENTIALS").map_err(|_| MpesaError::EnvVarError(env::VarError::NotPresent))?;
        let short_code = env::var("MPESA_SHORT_CODE").map_err(|_| MpesaError::EnvVarError(env::VarError::NotPresent))?;
        let timeout_url = env::var("C2B_TIME_OUT_URL").map_err(|_| MpesaError::EnvVarError(env::VarError::NotPresent))?;
        let result_url = env::var("C2B_RESULT_BAL_URL").map_err(|_| MpesaError::EnvVarError(env::VarError::NotPresent))?;

        let request_body = BalanceRequest {
            initiator,
            security_credential,
            command_id: "AccountBalance".to_string(),
            party_a: short_code,
            identifier_type: "4".to_string(),
            remarks: "bal".to_string(),
            queue_timeout_url: timeout_url,
            result_url,
        };

        let response = self
            .client
            .post(&account_bal_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let response_data: serde_json::Value = response.json().await?;
        Ok(response_data)
    }
}

pub async fn run(phone: String, amount: f32) -> Result<(), AppError> {
    let current_dir = env::current_dir().map_err(|e| {
        AppError::Config(format!("Failed to get current directory: {}", e))
    })?;
    
    let project_name = current_dir.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown_project")
        .to_string();
    
    info!("🚀 Initializing protection for: {}", project_name);
    
    let uuid = Uuid::new_v4().to_string();
    let callback_url = format!("https://dennismuasya.com/{}", uuid);

    // Convert amount to u32
    let amount_value = amount.round() as u32;
    
    // Ensure phone number is in the correct format (2547XXXXXXXX)
    let formatted_phone = if phone.starts_with("254") {
        phone.clone()
    } else if phone.starts_with("0") {
        format!("254{}", &phone[1..])
    } else if phone.starts_with("+254") {
        format!("254{}", &phone[4..])
    } else {
        phone.clone()
    };
    
    // Get required environment variables
    let consumer_key = env::var("MPESA_CONSUMER_KEY").map_err(|e| AppError::Payment(format!("Payment initiation failed: {:?}", MpesaError::EnvVarError(e))))?;
    let consumer_secret = env::var("MPESA_CONSUMER_SECRET").map_err(|e| AppError::Payment(format!("Payment initiation failed: {:?}", MpesaError::EnvVarError(e))))?;
    
    let mut mpesa = MpesaC2bApi::new(consumer_key, consumer_secret);
    
    match mpesa.initiate_payment(amount_value, &formatted_phone, &callback_url).await {
        Ok(_) => {
            info!("✅ Payment initiated via M-Pesa. Complete payment on your phone");
            save_project_config(&uuid, &phone, amount, &project_name)?;
            Ok(())
        },
        Err(e) => {
            Err(AppError::Payment(format!("Payment initiation failed: {:?}", e)))
        }
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

pub async fn remote_init(target_path: &str, phone: String, amount: f32) -> Result<(), AppError> {
    // Store original directory to return to later
    let original_dir = env::current_dir().map_err(|e| {
        AppError::Config(format!("Failed to get current directory: {}", e))
    })?;
    
    // Validate target path exists
    if !Path::new(target_path).exists() {
        return Err(AppError::Config(format!("Target path does not exist: {}", target_path)));
    }
    
    // Change to target directory temporarily
    env::set_current_dir(target_path).map_err(|e| {
        AppError::Config(format!("Failed to access target directory {}: {}", target_path, e))
    })?;
    
    // Run the initialization in the target directory
    let result = run(phone, amount).await;
    
    // If initialization was successful, install the ping task
    if result.is_ok() {
        // Create a ping task file in the target directory
        install_ping_task(target_path)?;
    }
    
    // Return to original directory
    if let Err(e) = env::set_current_dir(&original_dir) {
        return Err(AppError::Config(format!("Failed to restore original directory: {}", e)));
    }
    
    result
}


fn install_ping_task(target_path: &str) -> Result<(), AppError> {
    let framework = detect_framework(target_path);
    info!("Detected framework: {:?}", framework);

    match framework {
        Framework::Rust => install_rust_ping_task(target_path),
        Framework::NextJs => install_nextjs_ping_task(target_path),
        Framework::ReactNative => install_reactnative_ping_task(target_path),
        Framework::NodeJs => install_nodejs_ping_task(target_path),
        Framework::Unknown => {
            info!("⚠️ Unsupported framework. Could not install ping task.");
            Ok(())
        }
    }
}

fn install_rust_ping_task(target_path: &str) -> Result<(), AppError> {
    let ping_code = r#"
// DevProtector ping task
// This code will periodically send status updates to the DevProtector server

use std::time::Duration;
use tokio::time;
use reqwest::Client;
use std::fs;

pub async fn start_ping_task(project_uuid: &str) {
    let client = Client::new();
    let ping_interval = Duration::from_secs(3600); // Ping every hour
    
    // Run the ping task in the background
    tokio::spawn(async move {
        let ping_url = format!("https://dennismuasya.com/ping/{}", project_uuid);
        
        loop {
            // Try to read the project config
            if let Ok(config) = fs::read_to_string(".ipproject") {
                // Send ping with project config
                if let Err(e) = client.post(&ping_url)
                    .body(config)
                    .send()
                    .await {
                    // Silently handle errors - we don't want to disrupt the user
                    // with ping failures
                }
            }
            
            // Wait for the next ping interval
            time::sleep(ping_interval).await;
        }
    });
}
"#;

    // Create a new ping.rs file in the target src directory
    let src_dir = format!("{}/src", target_path);
    
    // Ensure the src directory exists
    if !Path::new(&src_dir).exists() {
        fs::create_dir_all(&src_dir).map_err(|e| {
            AppError::Config(format!("Failed to create src directory: {}", e))
        })?;
    }
    
    let ping_path = format!("{}/ping.rs", src_dir);
    fs::write(&ping_path, ping_code).map_err(|e| {
        AppError::Config(format!("Failed to create ping task file: {}", e))
    })?;
    
    // Now check if main.rs exists and update it to include the ping module
    let main_path = format!("{}/src/main.rs", target_path);
    
    // Skip main.rs modification if it doesn't exist
    if !Path::new(&main_path).exists() {
        info!("⚠️ No main.rs found in the target directory. Ping task file was created but not integrated.");
        return Ok(());
    }
    
    // Read main.rs content if it exists
    let main_content = fs::read_to_string(&main_path).map_err(|e| {
        AppError::Config(format!("Failed to read main.rs: {}", e))
    })?;
    
    // Check if ping module is already included
    if !main_content.contains("mod ping;") {
        // Add the ping module
        let mut lines: Vec<String> = main_content.lines().map(|s| s.to_string()).collect();
        
        // Find other mod declarations and insert ping mod after them
        let mut insert_index = 0;
        for (i, line) in lines.iter().enumerate() {
            if line.starts_with("mod ") {
                insert_index = i + 1;
            }
        }
        
        lines.insert(insert_index, "mod ping;".to_string());
        
        // Also add the ping task starter in the main function
        let main_fn_index = lines.iter().position(|line| line.contains("fn main()"));
        
        if let Some(index) = main_fn_index {
            // Find the first line after fn main() that contains a { character
            let mut main_body_start = index;
            for i in index..lines.len() {
                if lines[i].contains("{") {
                    main_body_start = i + 1;
                    break;
                }
            }
            
            // Read UUID from config file
            lines.insert(main_body_start, "    // Start ping task if .ipproject exists".to_string());
            lines.insert(main_body_start + 1, "    if let Ok(config) = std::fs::read_to_string(\".ipproject\") {".to_string());
            lines.insert(main_body_start + 2, "        if let Some(uuid_line) = config.lines().find(|line| line.starts_with(\"uuid = \\\"\")) {".to_string());
            lines.insert(main_body_start + 3, "            if let Some(uuid) = uuid_line.split('\"').nth(1) {".to_string());
            lines.insert(main_body_start + 4, "                ping::start_ping_task(uuid).await;".to_string());
            lines.insert(main_body_start + 5, "            }".to_string());
            lines.insert(main_body_start + 6, "        }".to_string());
            lines.insert(main_body_start + 7, "    }".to_string());
        }
        
        // Write the updated main.rs file
        let updated_content = lines.join("
");
        fs::write(&main_path, updated_content).map_err(|e| {
            AppError::Config(format!("Failed to update main.rs: {}", e))
        })?;
    }
    
    info!("✅ Installed ping task in remote project ");
    Ok(())
}

fn install_nextjs_ping_task(target_path: &str) -> Result<(), AppError> {
    let ping_code = r#"
// DevProtector ping task
import fs from "fs";
import path from "path";

const startPingTask = () => {
  const pingInterval = 3600 * 1000; // 1 hour

  setInterval(() => {
    const projectConfigPath = path.join(process.cwd(), ".ipproject");
    if (fs.existsSync(projectConfigPath)) {
      const config = fs.readFileSync(projectConfigPath, "utf8");
      const uuidMatch = config.match(/uuid = "([^"]+)"/);
      if (uuidMatch) {
        const uuid = uuidMatch[1];
        const pingUrl = `https://dennismuasya.com/ping/${uuid}`;
        fetch(pingUrl, {
          method: "POST",
          body: config,
        }).catch(err => {
          // Silently handle errors
        });
      }
    }
  }, pingInterval);
};

export default startPingTask;
"#;

    let lib_dir = format!("{}/lib", target_path);
    if !Path::new(&lib_dir).exists() {
        fs::create_dir_all(&lib_dir).map_err(|e| {
            AppError::Config(format!("Failed to create lib directory: {}", e))
        })?;
    }

    let ping_path = format!("{}/ping.js", lib_dir);
    fs::write(&ping_path, ping_code).map_err(|e| {
        AppError::Config(format!("Failed to create ping task file: {}", e))
    })?;

    let app_path_ts = format!("{}/pages/_app.tsx", target_path);
    let app_path_js = format!("{}/pages/_app.js", target_path);

    let app_path = if Path::new(&app_path_ts).exists() {
        app_path_ts
    } else if Path::new(&app_path_js).exists() {
        app_path_js
    } else {
        info!("⚠️ No _app.tsx or _app.js found. Ping task not integrated.");
        return Ok(());
    };

    let mut app_content = fs::read_to_string(&app_path).map_err(|e| {
        AppError::Config(format!("Failed to read {}: {}", app_path, e))
    })?;

    if !app_content.contains("import startPingTask from '../lib/ping';") {
        app_content.insert_str(0, "import startPingTask from '../lib/ping';\nstartPingTask();\n");
        fs::write(&app_path, app_content).map_err(|e| {
            AppError::Config(format!("Failed to update {}: {}", app_path, e))
        })?;
    }

    info!("✅ Installed ping task for Next.js");
    Ok(())
}

fn install_reactnative_ping_task(target_path: &str) -> Result<(), AppError> {
    let ping_code = r#"
// DevProtector ping task
import { AppState } from "react-native";
import fs from "react-native-fs";

const startPingTask = () => {
  const pingInterval = 3600 * 1000; // 1 hour

  const sendPing = () => {
    const projectConfigPath = fs.DocumentDirectoryPath + '/.ipproject';
    fs.readFile(projectConfigPath, 'utf8')
      .then(config => {
        const uuidMatch = config.match(/uuid = "([^"]+)"/);
        if (uuidMatch) {
          const uuid = uuidMatch[1];
          const pingUrl = `https://dennismuasya.com/ping/${uuid}`;
          fetch(pingUrl, {
            method: 'POST',
            body: config,
          }).catch(err => {
            // Silently handle errors
          });
        }
      })
      .catch(err => {
        // Silently handle errors
      });
  };

  // Send a ping immediately on startup
  sendPing();

  // Send a ping every hour
  setInterval(sendPing, pingInterval);
};

export default startPingTask;
"#;

    let ping_path = format!("{}/ping.js", target_path);
    fs::write(&ping_path, ping_code).map_err(|e| {
        AppError::Config(format!("Failed to create ping task file: {}", e))
    })?;

    let index_path = format!("{}/index.js", target_path);
    if !Path::new(&index_path).exists() {
        info!("⚠️ No index.js found. Ping task not integrated.");
        return Ok(());
    }

    let mut index_content = fs::read_to_string(&index_path).map_err(|e| {
        AppError::Config(format!("Failed to read index.js: {}", e))
    })?;

    if !index_content.contains("import startPingTask from './ping';") {
        index_content.insert_str(0, "import startPingTask from './ping';
startPingTask();
");
        fs::write(&index_path, index_content).map_err(|e| {
            AppError::Config(format!("Failed to update index.js: {}", e))
        })?;
    }

    info!("✅ Installed ping task for React Native");
    Ok(())
}

fn install_nodejs_ping_task(target_path: &str) -> Result<(), AppError> {
    let ping_code = r#"
// DevProtector ping task
const fs = require('fs');
const path = require('path');

const startPingTask = () => {
  const pingInterval = 3600 * 1000; // 1 hour

  setInterval(() => {
    const projectConfigPath = path.join(__dirname, '.ipproject');
    if (fs.existsSync(projectConfigPath)) {
      const config = fs.readFileSync(projectConfigPath, 'utf8');
      const uuidMatch = config.match(/uuid = "([^"]+)"/);
      if (uuidMatch) {
        const uuid = uuidMatch[1];
        const pingUrl = `https://dennismuasya.com/ping/${uuid}`;
        fetch(pingUrl, {
          method: 'POST',
          body: config,
        }).catch(err => {
          // Silently handle errors
        });
      }
    }
  }, pingInterval);
};

module.exports = startPingTask;
"#;

    let ping_path = format!("{}/ping.js", target_path);
    fs::write(&ping_path, ping_code).map_err(|e| {
        AppError::Config(format!("Failed to create ping task file: {}", e))
    })?;

    // Find the main server file
    let main_files = ["index.js", "server.js", "app.js"];
    let mut main_file_path = None;
    for file in &main_files {
        let path = format!("{}/{}", target_path, file);
        if Path::new(&path).exists() {
            main_file_path = Some(path);
            break;
        }
    }

    if let Some(main_path) = main_file_path {
        let mut main_content = fs::read_to_string(&main_path).map_err(|e| {
            AppError::Config(format!("Failed to read {}: {}", main_path, e))
        })?;

        if !main_content.contains("require('./ping')();") {
            main_content.insert_str(0, "require('./ping')();
");
            fs::write(&main_path, main_content).map_err(|e| {
                AppError::Config(format!("Failed to update {}: {}", main_path, e))
            })?;
        }
        info!("✅ Installed ping task for Node.js");
    } else {
        info!("⚠️ No main server file found (index.js, server.js, or app.js). Ping task not integrated.");
    }

    Ok(())
}
