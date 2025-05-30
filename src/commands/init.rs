use reqwest;
use serde_json::json;
use std::fs;
use uuid::Uuid;
use std::env;
use crate::error::AppError;
use tracing::info;

const MPESA_URL: &str = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest";

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
    let callback_url = format!("http://your-django-api/api/webhook/payment/{}", uuid);

    let payload = json!({
        "BusinessShortCode": "174379",
        "Password": "MTc0Mzc5YmZiMjc5ZjlhYTliZGJjZjE1OGU5N2RkNzFhNDY3Y2QyZTBjODkzMDU5YjEwZjc4ZTZiNzJhZGExZWQyYzkxOTIwMTYwMjE2MTY1NjI3",
        "Timestamp": "20160216165627",
        "TransactionType": "CustomerPayBillOnline",
        "Amount": "200",
        "PartyA": &phone,
        "PartyB": "174379",
        "PhoneNumber": &phone,
        "CallBackURL": &callback_url,
        "AccountReference": &uuid,
        "TransactionDesc": "IP Protection Fee"
    });

    let client = reqwest::Client::new();
    let res = client.post(MPESA_URL)
        .json(&payload)
        .send()
        .await
        .map_err(|e| AppError::Reqwest(e))?;

    if res.status().is_success() {
        info!("✅ Payment initiated via M-Pesa. Complete payment on your phone");
        save_project_config(&uuid, &phone, amount, &project_name)?;
        Ok(())
    } else {
        let error_text = res.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        Err(AppError::Payment(format!("Payment initiation failed: {}", error_text)))
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