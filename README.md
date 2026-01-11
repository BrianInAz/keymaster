# Keymaster - Vault Integration

Forked Keymaster with enhanced Vault authentication support for bjzy.me infrastructure.

## Purpose

Enables TouchID-based authentication for HashiCorp Vault access without storing passwords in plain text or requiring manual entry.

## Installation

```bash
# Compile the binary
swiftc keymaster.swift -o ~/.local/bin/keymaster

# Add to PATH if not already there
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
```

## Setup

```bash
# Store your vault password (one-time setup)
keymaster set vault-password "your-vault-password"

# Test retrieval
keymaster get vault-password
```

## Integration with .zshrc

Add this function to enable seamless vault authentication:

```bash
vault_check_login() {
    export VAULT_ADDR="https://vault.bjzy.me:8200"

    if ! vault token lookup >/dev/null 2>&1; then
        # TouchID prompt happens here
        VAULT_PASS=$(keymaster get vault-password 2>/dev/null)

        if [ -n "$VAULT_PASS" ]; then
            echo "$VAULT_PASS" | vault login -method=userpass username=b password=-
            unset VAULT_PASS
        else
            # Fallback to manual entry
            vault login -method=userpass username=b
        fi
    else
        vault token renew >/dev/null 2>&1 || true
        echo "✅ Vault session active"
    fi
}
```

## Security Features

- Passwords stored in macOS Keychain with biometric protection
- TouchID required for each access
- No plaintext passwords in shell history or scripts
- Automatic cleanup of password variables

## Usage

```bash
keymaster get vault-password    # Retrieve with TouchID
keymaster set vault-password "new-password"  # Store with TouchID
keymaster delete vault-password  # Remove from Keychain
```
