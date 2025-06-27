use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    
    #[error("HTTP request error: {0}")]
    Reqwest(#[from] reqwest::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("Framework detection error: {0}")]
    Framework(String),
    
    #[error("Injection error: {0}")]
    Injection(String),
    
    #[error("Payment error: {0}\nRequired ENV variables: OAUTH_URL, STK_PUSH_URL, MPESA_SHORT_CODE, C2B_PASS_KEY, MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET")]
    Payment(String),
    
    #[error("Unexpected error: {0}")]
    Other(String),
}

impl From<String> for AppError {
    fn from(value: String) -> Self {
        AppError::Other(value)
    }
}

impl From<&str> for AppError {
    fn from(value: &str) -> Self {
        AppError::Other(value.to_string())
    }
}