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

## Usage

DevProtector provides several commands to manage your project's protection:

```bash
# Display help information
devprotector --help

# Initialize project protection
devprotector init

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

## Examples

```bash
# Initialize protection in the current directory
devprotector init

# Encrypt files in a specific directory
devprotector -p /path/to/project encrypt

# Check status with verbose output
devprotector -v status
```

## License

[MIT](LICENSE)