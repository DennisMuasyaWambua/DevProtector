# DevProtector

A CLI tool for protecting your development projects through encryption.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/DevProtector.git
cd DevProtector

# Build the project
cargo build --release

# Optional: Install the binary
cargo install --path .
```

## How to Run

There are several ways to run DevProtector using Cargo:

```bash
# Run directly with cargo
cargo run -- --help

# Run a specific command
cargo run -- init
cargo run -- encrypt
cargo run -- status

# Run with arguments
cargo run -- -p /path/to/project encrypt
cargo run -- -v status
```

## Usage

DevProtector provides several commands to manage your project's protection:

```bash
# Display help information
devprotector --help

# Initialize project protection
devprotector init -p <phone_number> -a <amount>

# Initialize a remote project
devprotector init -p <phone_number> -a <amount> -r <remote_path>

# Encrypt project files
devprotector encrypt

# Check protection status
devprotector status
```

### Options

- `-p, --path <PATH>` - Specify a project directory path (default: current directory)
- `-v, --verbose` - Enable verbose logging
- `-h, --help` - Print help information
- `-V, --version` - Print version information

### Init Command Options

- `-p, --phone <PHONE>` - Phone number for payment verification
- `-a, --amount <AMOUNT>` - Amount to be paid for protection
- `-r, --remote <REMOTE_PATH>` - Initialize protection for a project in a different location

## Examples

```bash
# Initialize protection in the current directory
devprotector init -p 254712345678 -a 100

# Initialize protection in a remote project directory
devprotector init -p 254712345678 -a 100 -r /path/to/remote/project

# Encrypt files in a specific directory
devprotector -p /path/to/project encrypt

# Check status with verbose output
devprotector -v status
```

## License

[MIT](LICENSE)