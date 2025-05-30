use reqwest;
use std::env;
use crate::error::AppError;
use tracing::info;

pub async fn run() -> Result<(), AppError> {
    let current_dir = env::current_dir().map_err(|e| {
        AppError::Config(format!("Failed to get current directory: {}", e))
    })?;
    
    let project_name = current_dir.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown_project")
        .to_string();
    
    info!("📊 Checking protection status for: {}", project_name);

    let config = std::fs::read_to_string(".ipproject").map_err(|e| {
        AppError::Config(format!("Missing project config: {}", e))
    })?;
    
    let uuid = config.lines()
        .find(|l| l.starts_with("uuid"))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.trim().trim_matches('"'))
        .ok_or_else(|| AppError::Config("UUID not found in config".to_string()))?;

    // Check status once and return
    let status = check_payment_status(&uuid).await?;
    info!("🔄 Protection Status: {}", status);
    
    Ok(())
}

async fn check_payment_status(uuid: &str) -> Result<String, AppError> {
    let client = reqwest::Client::new();
    let response = client.get(&format!("http://your-django-api/api/projects/{}/status/", uuid))
        .send()
        .await
        .map_err(|e| AppError::Reqwest(e))?;

    if response.status().is_success() {
        let body: serde_json::Value = response.json().await
            .map_err(|e| AppError::Reqwest(e))?;
        Ok(body["encryption_status"].as_str().unwrap_or("unknown").to_string())
    } else {
        Ok("payment_pending".to_string())
    }
}