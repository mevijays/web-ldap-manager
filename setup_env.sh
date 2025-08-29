#!/bin/bash
# Environment Setup Script for LDAP Management Portal
# This script helps set up environment variables securely

echo "=== LDAP Management Portal Environment Setup ==="
echo

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Warning: Do not run this script as root. Run as the ldapman user."
    exit 1
fi

# Function to generate random secret key
generate_secret_key() {
    python3 -c "import secrets; print(secrets.token_hex(32))"
}

# Check if config directory exists
CONFIG_DIR="/home/ldapman/pythonldapman/config"
ENV_FILE="$CONFIG_DIR/production.env"

echo "Checking configuration setup..."

# Create config directory if it doesn't exist
if [ ! -d "$CONFIG_DIR" ]; then
    echo "Creating config directory..."
    mkdir -p "$CONFIG_DIR"
fi

# Check if environment file exists
if [ -f "$ENV_FILE" ]; then
    echo "Environment file already exists: $ENV_FILE"
    echo "Do you want to recreate it? (y/N): "
    read -r RECREATE
    if [ "$RECREATE" != "y" ] && [ "$RECREATE" != "Y" ]; then
        echo "Keeping existing configuration."
        echo "To edit manually: nano $ENV_FILE"
        exit 0
    fi
fi

echo
echo "Setting up environment configuration..."
echo

# Prompt for LDAP admin password
echo -n "Enter LDAP Admin Password: "
read -s LDAP_ADMIN_PASSWORD
echo
echo -n "Confirm LDAP Admin Password: "
read -s LDAP_ADMIN_PASSWORD_CONFIRM
echo

if [ "$LDAP_ADMIN_PASSWORD" != "$LDAP_ADMIN_PASSWORD_CONFIRM" ]; then
    echo "Error: Passwords do not match!"
    exit 1
fi

if [ -z "$LDAP_ADMIN_PASSWORD" ]; then
    echo "Error: Password cannot be empty!"
    exit 1
fi

# Generate secret key
SECRET_KEY=$(generate_secret_key)

echo
echo "Creating environment file..."

# Create environment file
cat > "$ENV_FILE" << EOF
# Flask Configuration
FLASK_ENV=production
SECRET_KEY=$SECRET_KEY
SESSION_TYPE=filesystem

# LDAP Configuration
LDAP_SERVER=192.168.1.1
LDAP_PORT=389
LDAP_BASE_DN=dc=mylab,dc=lan
LDAP_ADMIN_DN=cn=admin,dc=mylab,dc=lan
LDAP_ADMIN_PASSWORD=$LDAP_ADMIN_PASSWORD

# Application Settings
DEBUG=False
HOST=0.0.0.0
PORT=5000
EOF

# Set secure permissions
chmod 600 "$ENV_FILE"

echo "✅ Environment file created successfully!"
echo "📁 Location: $ENV_FILE"
echo "🔒 Permissions set to 600 (read/write for owner only)"
echo
echo "Next steps:"
echo "1. Test the configuration: cd /home/ldapman/pythonldapman && source .venv/bin/activate && python app.py"
echo "2. Set up systemd service as described in INSTALLATION.md"
echo
echo "🛡️  Security reminder: Never commit this file to version control!"
