# LDAP Management Portal - Complete Setup Guide

This guide provides comprehensive instructions for setting up the LDAP Management Portal on Ubuntu 24.04, including LDAP server installation, configuration, and running the portal as a systemd service.

## Table of Contents
1. [LDAP Server Setup (OpenLDAP on Ubuntu 24.04)](#1-ldap-server-setup)
2. [Python Application Installation](#2-python-application-installation)  
3. [System Service Configuration](#3-system-service-configuration)
4. [Production Configuration](#4-production-configuration)
5. [Testing and Verification](#5-testing-and-verification)

---

## 1. LDAP Server Setup

### 1.1 Install OpenLDAP Server

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install OpenLDAP server and utilities
sudo apt install -y slapd ldap-utils

# Reconfigure slapd for initial setup
sudo dpkg-reconfigure slapd
```

**During the reconfiguration, provide these settings:**
- Omit OpenLDAP server configuration? **No**
- DNS domain name: `mylab.lan` (or your preferred domain)
- Organization name: `MyLab` (or your organization)
- Administrator password: Choose a strong password (remember this!)
- Database backend: **MDB**
- Do you want the database to be removed when slapd is purged? **No**
- Move old database? **Yes**

### 1.2 Configure Base DN Structure

Create the base organizational structure:

```bash
# Create base structure LDIF file
cat > /tmp/base_structure.ldif << 'EOF'
dn: ou=People,dc=mylab,dc=lan
objectClass: organizationalUnit
ou: People
description: Container for user accounts

dn: ou=Groups,dc=mylab,dc=lan
objectClass: organizationalUnit
ou: Groups
description: Container for groups

dn: cn=admins,ou=Groups,dc=mylab,dc=lan
objectClass: groupOfNames
cn: admins
description: Administrative group
member: cn=admin,dc=mylab,dc=lan
EOF

# Add the base structure to LDAP
sudo ldapadd -x -D "cn=admin,dc=mylab,dc=lan" -W -f /tmp/base_structure.ldif
```

### 1.3 Configure LDAP Schema (Optional - for advanced features)

Enable additional schemas for POSIX support:

```bash
# Enable POSIX schema
sudo ldapmodify -Y EXTERNAL -H ldapi:/// << 'EOF'
dn: cn=module,cn=config
changetype: add
objectClass: olcModuleList
cn: module
olcModulepath: /usr/lib/ldap
olcModuleload: memberof
olcModuleload: refint
EOF

# Configure memberOf overlay
sudo ldapmodify -Y EXTERNAL -H ldapi:/// << 'EOF'
dn: olcOverlay={0}memberof,olcDatabase={1}mdb,cn=config
changetype: add
objectClass: olcConfig
objectClass: olcMemberOf
olcOverlay: {0}memberof
olcMemberOfDangling: ignore
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: groupOfNames
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf
EOF
```

### 1.4 Create Sample Users (Optional)

```bash
# Create sample users LDIF
cat > /tmp/sample_users.ldif << 'EOF'
dn: uid=john.doe,ou=People,dc=mylab,dc=lan
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: john.doe
cn: John Doe
givenName: John
sn: Doe
mail: john.doe@mylab.lan
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/john.doe
loginShell: /bin/bash
userPassword: {SSHA}generatethispassword

dn: uid=jane.smith,ou=People,dc=mylab,dc=lan
objectClass: inetOrgPerson
uid: jane.smith
cn: Jane Smith
givenName: Jane
sn: Smith
mail: jane.smith@mylab.lan
userPassword: {SSHA}generatethispassword

dn: cn=linuxusers,ou=Groups,dc=mylab,dc=lan
objectClass: posixGroup
cn: linuxusers
gidNumber: 1001
memberUid: john.doe
EOF

# Add sample users (set proper passwords first)
# sudo ldapadd -x -D "cn=admin,dc=mylab,dc=lan" -W -f /tmp/sample_users.ldif
```

### 1.5 Configure LDAP Access Controls

```bash
# Create access control configuration
sudo ldapmodify -Y EXTERNAL -H ldapi:/// << 'EOF'
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to attrs=shadowLastChange by self write by * read
olcAccess: {2}to * by self write by users read by anonymous auth by * none
EOF
```

---

## 2. Python Application Installation

### 2.1 System Requirements

```bash
# Install Python and system dependencies
sudo apt install -y python3 python3-pip python3-venv git nginx

# Install additional packages for image processing
sudo apt install -y libjpeg-dev libpng-dev libtiff-dev libwebp-dev
```

### 2.2 Application Setup

```bash
# Create application directory
sudo mkdir -p /opt/ldap-portal
sudo chown $USER:$USER /opt/ldap-portal
cd /opt/ldap-portal

# Clone or copy your application files
# git clone <your-repo> .
# OR copy your files to /opt/ldap-portal/

# Create Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 2.3 Environment Configuration

```bash
# Create environment file
sudo mkdir -p /etc/ldap-portal
sudo tee /etc/ldap-portal/config.env << 'EOF'
# LDAP Server Configuration
LDAP_SERVER=localhost
LDAP_PORT=389
LDAP_BASE_DN=dc=mylab,dc=lan
LDAP_ADMIN_DN=cn=admin,dc=mylab,dc=lan
LDAP_ADMIN_PASSWORD=your_admin_password_here

# Flask Configuration
FLASK_ENV=production
SECRET_KEY=your_secret_key_here
SESSION_TYPE=filesystem
DEBUG_MODE=false
EOF

# Secure the configuration file
sudo chmod 600 /etc/ldap-portal/config.env
sudo chown www-data:www-data /etc/ldap-portal/config.env
```

### 2.4 Application User Setup

```bash
# Create dedicated user for the application
sudo useradd -r -s /bin/false -d /opt/ldap-portal ldap-portal
sudo chown -R ldap-portal:ldap-portal /opt/ldap-portal

# Create directories for Flask session storage
sudo mkdir -p /var/lib/ldap-portal/sessions
sudo chown -R ldap-portal:ldap-portal /var/lib/ldap-portal
sudo chmod 750 /var/lib/ldap-portal
```

---

## 3. System Service Configuration

### 3.1 Create Systemd Service

```bash
# Create systemd service file
sudo tee /etc/systemd/system/ldap-portal.service << 'EOF'
[Unit]
Description=LDAP Management Portal
After=network.target slapd.service
Requires=slapd.service

[Service]
Type=simple
User=ldap-portal
Group=ldap-portal
WorkingDirectory=/opt/ldap-portal
Environment=PATH=/opt/ldap-portal/.venv/bin
EnvironmentFile=/etc/ldap-portal/config.env
ExecStart=/opt/ldap-portal/.venv/bin/python app.py
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/ldap-portal /var/lib/ldap-portal
NoNewPrivileges=true

# Restart configuration
Restart=on-failure
RestartSec=10
StartLimitBurst=3
StartLimitInterval=60

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable the service
sudo systemctl daemon-reload
sudo systemctl enable ldap-portal.service
```

### 3.2 Configure Nginx Reverse Proxy (Optional but Recommended)

```bash
# Create Nginx site configuration
sudo tee /etc/nginx/sites-available/ldap-portal << 'EOF'
server {
    listen 80;
    server_name ldap-portal.mylab.lan;  # Change to your domain
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Client max body size for file uploads
    client_max_body_size 10M;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Static files (if any)
    location /static/ {
        alias /opt/ldap-portal/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF

# Enable the site
sudo ln -s /etc/nginx/sites-available/ldap-portal /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 3.3 Configure Firewall

```bash
# Configure UFW firewall
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 389/tcp  # LDAP
sudo ufw --force enable
```

---

## 4. Production Configuration

### 4.1 SSL/TLS Setup with Let's Encrypt (Optional)

```bash
# Install certbot
sudo apt install -y certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d ldap-portal.mylab.lan

# Test automatic renewal
sudo certbot renew --dry-run
```

### 4.2 Logging Configuration

```bash
# Create log directories
sudo mkdir -p /var/log/ldap-portal
sudo chown ldap-portal:ldap-portal /var/log/ldap-portal

# Configure log rotation
sudo tee /etc/logrotate.d/ldap-portal << 'EOF'
/var/log/ldap-portal/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 ldap-portal ldap-portal
    postrotate
        systemctl reload ldap-portal
    endscript
}
EOF
```

### 4.3 Update App Configuration for Production

Modify your `app.py` to use proper logging in production:

```python
# Add at the top of app.py
import logging
from logging.handlers import RotatingFileHandler
import os

# Configure logging for production
if not app.debug:
    if not os.path.exists('/var/log/ldap-portal'):
        os.makedirs('/var/log/ldap-portal')
    
    file_handler = RotatingFileHandler(
        '/var/log/ldap-portal/app.log', 
        maxBytes=10240000, 
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('LDAP Portal startup')

# Change the app.run() configuration
if __name__ == '__main__':
    # Production configuration
    app.run(host='127.0.0.1', port=5000, debug=False)
```

---

## 5. Testing and Verification

### 5.1 Start Services

```bash
# Start LDAP server
sudo systemctl start slapd
sudo systemctl status slapd

# Start the LDAP portal
sudo systemctl start ldap-portal
sudo systemctl status ldap-portal

# Check logs
sudo journalctl -u ldap-portal -f
```

### 5.2 Verify LDAP Server

```bash
# Test LDAP connection
ldapsearch -x -H ldap://localhost -D "cn=admin,dc=mylab,dc=lan" -W -b "dc=mylab,dc=lan"

# List users
ldapsearch -x -H ldap://localhost -D "cn=admin,dc=mylab,dc=lan" -W -b "ou=People,dc=mylab,dc=lan"

# List groups
ldapsearch -x -H ldap://localhost -D "cn=admin,dc=mylab,dc=lan" -W -b "ou=Groups,dc=mylab,dc=lan"
```

### 5.3 Test Web Application

```bash
# Test local connection
curl http://localhost:5000

# Test through Nginx (if configured)
curl http://ldap-portal.mylab.lan
```

### 5.4 Verify Service Auto-Start

```bash
# Reboot to test auto-start
sudo reboot

# After reboot, check services
sudo systemctl status slapd
sudo systemctl status ldap-portal
```

---

## 6. Maintenance and Troubleshooting

### 6.1 Common Service Commands

```bash
# Service management
sudo systemctl start ldap-portal
sudo systemctl stop ldap-portal
sudo systemctl restart ldap-portal
sudo systemctl reload ldap-portal
sudo systemctl status ldap-portal

# View logs
sudo journalctl -u ldap-portal -f
sudo tail -f /var/log/ldap-portal/app.log
```

### 6.2 Backup Configuration

```bash
# Backup LDAP data
sudo slapcat -l /backup/ldap-backup-$(date +%Y%m%d).ldif

# Backup application
sudo tar -czf /backup/ldap-portal-$(date +%Y%m%d).tar.gz /opt/ldap-portal /etc/ldap-portal
```

### 6.3 Common Issues

**LDAP Connection Issues:**
- Check if slapd service is running: `sudo systemctl status slapd`
- Verify LDAP server is listening: `sudo netstat -tlnp | grep :389`
- Check LDAP logs: `sudo journalctl -u slapd -f`

**Web Application Issues:**
- Check application logs: `sudo journalctl -u ldap-portal -f`
- Verify Python environment: `source /opt/ldap-portal/.venv/bin/activate && python --version`
- Check file permissions: `sudo ls -la /opt/ldap-portal`

**Permission Issues:**
- Ensure proper ownership: `sudo chown -R ldap-portal:ldap-portal /opt/ldap-portal`
- Check config file: `sudo ls -la /etc/ldap-portal/config.env`

---

## 7. Security Hardening

### 7.1 LDAP Security

```bash
# Enable TLS for LDAP (recommended for production)
sudo ldapmodify -Y EXTERNAL -H ldapi:/// << 'EOF'
dn: cn=config
changetype: modify
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ssl/certs/ldap-server.crt
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ssl/private/ldap-server.key
EOF
```

### 7.2 Application Security

```bash
# Set proper file permissions
sudo chmod 600 /etc/ldap-portal/config.env
sudo chmod 755 /opt/ldap-portal
sudo chmod 644 /opt/ldap-portal/app.py

# Enable fail2ban for additional protection
sudo apt install -y fail2ban
```

---

## 8. Feature-Specific Configuration

### 8.1 Photo Upload Configuration

Ensure image processing libraries are available:

```bash
# Install system image libraries
sudo apt install -y libjpeg-dev libpng-dev libtiff-dev libwebp-dev

# Verify Pillow installation
source /opt/ldap-portal/.venv/bin/activate
python -c "from PIL import Image; print('PIL/Pillow is working')"
```

### 8.2 Bulk User Import Configuration

The application supports CSV bulk user imports. No additional configuration needed.

### 8.3 Statistics Dashboard

The statistics dashboard automatically collects LDAP server metrics. Ensure the admin account has proper read permissions.

---

This completes the comprehensive setup guide for the LDAP Management Portal. The application will now run as a system service and automatically start on boot.

For ongoing maintenance, monitor the system logs and keep the system updated with security patches.
