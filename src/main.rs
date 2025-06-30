mod commands;
mod error;

use clap::{Parser, Subcommand};
use commands::{init, encrypt, status};
use std::{env, process};
use std::path::Path;
use tracing::{error, Level};
use tracing_subscriber;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Project directory path
    #[arg(short, long, default_value = ".")]
    path: String,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize project protection
    Init {
        #[arg(short, long)]
        phone: String,
        #[arg(short, long)]
        amount: f32,
    },
    /// Encrypt project files
    Encrypt,
    /// Check protection status
    Status,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    // Configure logging
    let log_level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    let target_path = Path::new(&cli.path);
    
    // Store original working directory
    let original_dir = env::current_dir().unwrap_or_else(|e| {
        error!("Failed to get current directory: {}", e);
        process::exit(1);
    });
    
    // Change to target directory if needed
    if cli.path != "." {
        if let Err(e) = env::set_current_dir(&target_path) {
            error!("❌ Failed to access project directory: {}", e);
            process::exit(1);
        }
    }

    // Handle the command and store the result
    let result = match cli.command {
        Commands::Init { phone, amount } => init::run(phone, amount).await,
        Commands::Encrypt => encrypt::run().await,
        Commands::Status => status::run().await,
    };

    // Restore original working directory
    if let Err(e) = env::set_current_dir(&original_dir) {
        error!("⚠️ Warning: Failed to restore working directory: {}", e);
    }

    // Handle the command result
    if let Err(e) = result {
        error!("❌ Operation failed: {}", e);
        process::exit(1);
    }
}