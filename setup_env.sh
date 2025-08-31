#!/bin/bash
# Complete LDAP Server Setup Script for Ubuntu 24.04
# This script installs slapd server, configures ACL policies, and sets up the environment

set -e  # Exit on any error

echo "=== Complete LDAP Server & Management Portal Setup ==="
echo "This script will:"
echo "1. Install and configure slapd server on Ubuntu 24.04"
echo "2. Set up ACL policies for user self-service"
echo "3. Create People and Groups OUs"
echo "4. Configure the LDAP Management Portal environment"
echo

# Check if running on Ubuntu 24.04
if ! grep -q "Ubuntu 24.04" /etc/os-release 2>/dev/null; then
    echo "⚠️  Warning: This script is designed for Ubuntu 24.04"
    echo "Continue anyway? (y/N): "
    read -r CONTINUE
    if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
        exit 1
    fi
fi

# Check if running as root for system installation
if [ "$EUID" -eq 0 ]; then
    echo "Running as root - system installation mode"
    SYSTEM_INSTALL=true
else
    echo "Running as regular user - environment configuration mode"
    SYSTEM_INSTALL=false
fi

# Function to generate random secret key
generate_secret_key() {
    python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || \
    openssl rand -hex 32 2>/dev/null || \
    head -c 32 /dev/urandom | base64 | tr -d '=+/' | head -c 32
}

# Function to generate random password
generate_password() {
    local length=${1:-16}
    openssl rand -base64 $((length * 3 / 4)) | tr -d '=+/' | head -c $length
}

# Function to install slapd server
install_slapd_server() {
    echo
    echo "=== Installing slapd Server ==="
    
    # Update package list
    echo "📦 Updating package list..."
    apt-get update -qq
    
    # Pre-configure slapd to avoid interactive prompts
    echo "🔧 Pre-configuring slapd..."
    
    # Set up debconf selections for slapd
    echo "slapd slapd/internal/generated_adminpw password $LDAP_ADMIN_PASSWORD" | debconf-set-selections
    echo "slapd slapd/internal/adminpw password $LDAP_ADMIN_PASSWORD" | debconf-set-selections
    echo "slapd slapd/password2 password $LDAP_ADMIN_PASSWORD" | debconf-set-selections
    echo "slapd slapd/password1 password $LDAP_ADMIN_PASSWORD" | debconf-set-selections
    echo "slapd slapd/dump_database_destdir string /var/backups/slapd-VERSION" | debconf-set-selections
    echo "slapd slapd/domain string $DOMAIN" | debconf-set-selections
    echo "slapd shared/organization string $ORGANIZATION" | debconf-set-selections
    echo "slapd slapd/backend string MDB" | debconf-set-selections
    echo "slapd slapd/purge_database boolean true" | debconf-set-selections
    echo "slapd slapd/move_old_database boolean true" | debconf-set-selections
    echo "slapd slapd/allow_ldap_v2 boolean false" | debconf-set-selections
    echo "slapd slapd/no_configuration boolean false" | debconf-set-selections
    echo "slapd slapd/dump_database boolean when_needed" | debconf-set-selections
    
    # Install slapd and ldap-utils
    echo "📦 Installing slapd and ldap-utils..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y slapd ldap-utils
    
    # Start and enable slapd service
    echo "🚀 Starting slapd service..."
    systemctl start slapd
    systemctl enable slapd
    
    # Verify installation
    if systemctl is-active --quiet slapd; then
        echo "✅ slapd server installed and running successfully!"
    else
        echo "❌ Failed to start slapd server"
        exit 1
    fi
}

# Function to configure LDAP schemas and OUs
configure_ldap_structure() {
    echo
    echo "=== Configuring LDAP Structure ==="
    
    # Create temporary directory for LDIF files
    TEMP_DIR="/tmp/ldap_setup_$$"
    mkdir -p "$TEMP_DIR"
    
    # Create base OU structure
    echo "📁 Creating organizational units..."
    
    cat > "$TEMP_DIR/base_structure.ldif" << EOF
# Create People OU
dn: ou=People,$BASE_DN
objectClass: top
objectClass: organizationalUnit
ou: People
description: Container for user accounts

# Create Groups OU  
dn: ou=Groups,$BASE_DN
objectClass: top
objectClass: organizationalUnit
ou: Groups
description: Container for group accounts
EOF

    # Apply base structure
    ldapadd -x -D "$ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f "$TEMP_DIR/base_structure.ldif"
    
    echo "✅ Base OU structure created successfully!"
}

# Function to configure ACL policies
configure_acl_policies() {
    echo
    echo "=== Configuring ACL Policies ==="
    
    # Create ACL configuration for user self-service
    cat > "$TEMP_DIR/acl_policies.ldif" << EOF
# Allow users to modify their own attributes
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange
  by dn="$ADMIN_DN" write
  by anonymous auth
  by self write
  by * none
olcAccess: {1}to attrs=cn,mail,telephoneNumber,displayName,givenName,sn,description,jpegPhoto,loginShell,gecos
  by dn="$ADMIN_DN" write
  by self write
  by * read
olcAccess: {2}to dn.subtree="ou=People,$BASE_DN"
  by dn="$ADMIN_DN" write
  by self write
  by * read
olcAccess: {3}to dn.subtree="ou=Groups,$BASE_DN"
  by dn="$ADMIN_DN" write
  by * read
olcAccess: {4}to *
  by dn="$ADMIN_DN" write
  by * read
EOF

    # Apply ACL policies
    ldapmodify -Y EXTERNAL -H ldapi:/// -f "$TEMP_DIR/acl_policies.ldif"
    
    echo "✅ ACL policies configured successfully!"
    echo "   - Users can modify their own attributes"
    echo "   - Users can update profile information"
    echo "   - Admin has full access"
    echo "   - Public read access for directory browsing"
}

# Function to add required schemas
add_ldap_schemas() {
    echo
    echo "=== Adding LDAP Schemas ==="
    
    # Add POSIX schema for Unix accounts
    echo "📚 Adding POSIX schema..."
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/ldap/schema/cosine.ldif 2>/dev/null || echo "   cosine schema already exists"
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/ldap/schema/nis.ldif 2>/dev/null || echo "   nis schema already exists"
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/ldap/schema/inetorgperson.ldif 2>/dev/null || echo "   inetorgperson schema already exists"
    
    echo "✅ Required schemas configured!"
}

# Function to create sample users and groups (optional)
create_sample_data() {
    echo
    echo "Do you want to create sample users and groups for testing? (y/N): "
    read -r CREATE_SAMPLES
    
    if [ "$CREATE_SAMPLES" = "y" ] || [ "$CREATE_SAMPLES" = "Y" ]; then
        echo "📝 Creating sample data..."
        
        cat > "$TEMP_DIR/sample_data.ldif" << EOF
# Sample group
dn: cn=developers,ou=Groups,$BASE_DN
objectClass: top
objectClass: posixGroup
cn: developers
gidNumber: 10000
description: Development team group

# Sample user
dn: cn=testuser,ou=People,$BASE_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: testuser
sn: User
givenName: Test
displayName: Test User
mail: testuser@$DOMAIN
uid: testuser
uidNumber: 10001
gidNumber: 10000
homeDirectory: /home/testuser
loginShell: /bin/bash
userPassword: {SSHA}$(slappasswd -s 'password123')
shadowLastChange: 0
shadowMax: 99999
shadowWarning: 7
EOF

        ldapadd -x -D "$ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f "$TEMP_DIR/sample_data.ldif"
        echo "✅ Sample data created!"
        echo "   Test user: testuser / password123"
        echo "   Test group: developers"
    fi
}

# Function to configure environment for the web application
configure_web_environment() {
    echo
    echo "=== Configuring Web Application Environment ==="
    
    # Determine the correct user and directories
    if [ "$SYSTEM_INSTALL" = true ]; then
        # Running as root, set up for ldapman user
        WEB_USER="ldapman"
        WEB_HOME="/home/ldapman"
        CONFIG_DIR="$WEB_HOME/pythonldapman/config"
    else
        # Running as regular user
        WEB_USER=$(whoami)
        WEB_HOME="$HOME"
        CONFIG_DIR="$PWD/config"
    fi
    
    ENV_FILE="$CONFIG_DIR/production.env"
    
    echo "Setting up environment for user: $WEB_USER"
    echo "Configuration directory: $CONFIG_DIR"
    
    # Create config directory if it doesn't exist
    if [ ! -d "$CONFIG_DIR" ]; then
        echo "Creating config directory..."
        mkdir -p "$CONFIG_DIR"
        if [ "$SYSTEM_INSTALL" = true ]; then
            chown -R ldapman:ldapman "$CONFIG_DIR"
        fi
    fi
    
    # Check if environment file exists
    if [ -f "$ENV_FILE" ]; then
        echo "Environment file already exists: $ENV_FILE"
        echo "Do you want to recreate it? (y/N): "
        read -r RECREATE
        if [ "$RECREATE" != "y" ] && [ "$RECREATE" != "Y" ]; then
            echo "Keeping existing configuration."
            return 0
        fi
    fi
    
    # Generate secret key
    SECRET_KEY=$(generate_secret_key)
    
    echo "Creating environment file..."
    
    # Create environment file
    cat > "$ENV_FILE" << EOF
# Flask Configuration
FLASK_ENV=production
SECRET_KEY=$SECRET_KEY
SESSION_TYPE=filesystem

# LDAP Configuration
LDAP_SERVER=127.0.0.1
LDAP_PORT=389
LDAP_BASE_DN=$BASE_DN
LDAP_ADMIN_DN=$ADMIN_DN
LDAP_ADMIN_PASSWORD=$LDAP_ADMIN_PASSWORD

# Application Settings
DEBUG_MODE=false
HOST=127.0.0.1
PORT=5000
EOF

    # Set secure permissions
    chmod 600 "$ENV_FILE"
    if [ "$SYSTEM_INSTALL" = true ]; then
        chown ldapman:ldapman "$ENV_FILE"
    fi
    
    echo "✅ Environment file created successfully!"
    echo "📁 Location: $ENV_FILE"
    echo "🔒 Permissions set to 600 (read/write for owner only)"
}

# Main execution flow
main() {
    echo "Setup mode selection:"
    echo "1. Complete installation (install slapd + configure web app)"
    echo "2. Environment configuration only"
    echo "3. slapd server installation only"
    echo
    echo -n "Select option (1-3): "
    read -r SETUP_MODE
    
    case $SETUP_MODE in
        1)
            echo "Selected: Complete installation"
            if [ "$SYSTEM_INSTALL" != true ]; then
                echo "❌ Complete installation requires root privileges"
                echo "Please run: sudo $0"
                exit 1
            fi
            ;;
        2)
            echo "Selected: Environment configuration only"
            configure_web_environment
            echo
            echo "🎉 Environment configuration completed!"
            echo "To start the application:"
            echo "1. cd $(dirname "$0")"
            echo "2. source .venv/bin/activate"
            echo "3. python app.py"
            exit 0
            ;;
        3)
            echo "Selected: slapd server installation only"
            if [ "$SYSTEM_INSTALL" != true ]; then
                echo "❌ slapd installation requires root privileges"
                echo "Please run: sudo $0"
                exit 1
            fi
            ;;
        *)
            echo "❌ Invalid selection"
            exit 1
            ;;
    esac
    
    # Get domain information for LDAP setup
    echo
    echo "=== LDAP Domain Configuration ==="
    echo -n "Enter your domain (e.g., mylab.lan): "
    read -r DOMAIN
    
    if [ -z "$DOMAIN" ]; then
        echo "Using default domain: mylab.lan"
        DOMAIN="mylab.lan"
    fi
    
    echo -n "Enter organization name (e.g., My Lab): "
    read -r ORGANIZATION
    
    if [ -z "$ORGANIZATION" ]; then
        echo "Using default organization: My Lab"
        ORGANIZATION="My Lab"
    fi
    
    # Convert domain to DN format
    BASE_DN=$(echo "$DOMAIN" | sed 's/\./,dc=/g' | sed 's/^/dc=/')
    ADMIN_DN="cn=admin,$BASE_DN"
    
    echo
    echo "Configuration:"
    echo "  Domain: $DOMAIN"
    echo "  Organization: $ORGANIZATION"
    echo "  Base DN: $BASE_DN"
    echo "  Admin DN: $ADMIN_DN"
    echo
    
    # Get LDAP admin password
    if [ "$SETUP_MODE" = "1" ] || [ "$SETUP_MODE" = "3" ]; then
        echo "=== LDAP Admin Password Setup ==="
        echo "⚠️  This password will be used for LDAP admin authentication"
        echo -n "Enter LDAP Admin Password: "
        read -s LDAP_ADMIN_PASSWORD
        echo
        echo -n "Confirm LDAP Admin Password: "
        read -s LDAP_ADMIN_PASSWORD_CONFIRM
        echo
        
        if [ "$LDAP_ADMIN_PASSWORD" != "$LDAP_ADMIN_PASSWORD_CONFIRM" ]; then
            echo "❌ Passwords do not match!"
            exit 1
        fi
        
        if [ -z "$LDAP_ADMIN_PASSWORD" ]; then
            echo "❌ Password cannot be empty!"
            exit 1
        fi
        
        echo "✅ Password confirmed"
    fi
    
    # Install and configure slapd if requested
    if [ "$SETUP_MODE" = "1" ] || [ "$SETUP_MODE" = "3" ]; then
        install_slapd_server
        add_ldap_schemas
        configure_ldap_structure
        configure_acl_policies
        create_sample_data
        
        echo
        echo "🎉 slapd server installation completed!"
        echo
        echo "🔧 Server Details:"
        echo "   LDAP URI: ldap://127.0.0.1:389"
        echo "   Base DN: $BASE_DN"
        echo "   Admin DN: $ADMIN_DN"
        echo "   People OU: ou=People,$BASE_DN"
        echo "   Groups OU: ou=Groups,$BASE_DN"
        echo
        echo "🧪 Test connection:"
        echo "   ldapsearch -x -H ldap://127.0.0.1 -D \"$ADMIN_DN\" -W -b \"$BASE_DN\""
        echo
    fi
    
    # Configure web application environment if complete installation
    if [ "$SETUP_MODE" = "1" ]; then
        configure_web_environment
        
        echo
        echo "🎉 Complete installation finished!"
        echo
        echo "📋 Next Steps:"
        echo "1. Test LDAP connection:"
        echo "   ldapsearch -x -H ldap://127.0.0.1 -D \"$ADMIN_DN\" -W -b \"$BASE_DN\""
        echo
        echo "2. Start the web application:"
        echo "   su - ldapman"
        echo "   cd pythonldapman"
        echo "   source .venv/bin/activate"
        echo "   python app.py"
        echo
        echo "3. Access the web interface:"
        echo "   http://127.0.0.1:5000"
        echo
        echo "4. Set up systemd service (optional):"
        echo "   See SETUP.md for systemd service configuration"
    fi
    
    # Cleanup
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

# Run main function
main
