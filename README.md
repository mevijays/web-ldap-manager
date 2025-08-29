# LDAP Management Portal

A comprehensive Flask-based web application for LDAP administration and user self-service portal built with Bootstrap 5.

## Features

### 👤 User Self-Service Portal
- **User Login**: Normal users can login with their LDAP credentials
- **Profile Management**: Users can update their personal information (email, phone, description, etc.)
- **Profile Photos**: Upload and manage profile photos using jpegPhoto attribute with automatic resizing
- **Password Change**: Secure password change functionality with SSHA encryption
- **Password Expiry Information**: View password expiry status and remaining days (POSIX users)
- **User Directory**: Browse and search other users in the organization
- **Clean Dashboard**: Intuitive interface showing account status and quick actions

### 🛡️ Multi-Tier Admin System
#### Super Administrator (`cn=admin,dc=mylab,dc=lan`)
- **Full system access** with all administrative privileges
- **System account protection** (cannot modify own profile)
- **Login**: Use username `admin` with admin DN credentials

#### Group Administrators (members of `cn=admins` group)
- **User management** capabilities
- **Group management** access
- **Limited administrative privileges**
- **Self-profile modification** allowed

### 🔧 Administrative Features
- ✅ **Complete User Management**: Create, read, update, delete user accounts
- ✅ **POSIX User Support**: Create users with POSIX attributes (UID, GID, home directory, shell)
- ✅ **Complete Group Management**: 
  - Create both standard and POSIX groups
  - Delete existing groups
  - Add/remove members from groups
  - View group membership details
- ✅ **Bulk User Creation**: Upload CSV files to create multiple users at once
- ✅ **Profile Photo Management**: Upload, preview, and manage user photos (jpegPhoto attribute)
- ✅ **Password Expiry Management**: View and manage password expiration for POSIX users
- ✅ **User Search & Filtering**: Search users by name, email, or other attributes
- ✅ **Comprehensive Statistics**: LDAP server statistics dashboard with user/group counts
- ✅ **Generic Entry Editor**: Edit any LDAP entry with all attributes
- ✅ **Lock/Unlock Users**: Temporarily disable user accounts
- ✅ **Admin Dashboard**: Comprehensive administrative interface with real-time statistics
- ✅ **Security Features**: Environment-based configuration, secure password handling

## Technology Stack

- **Backend**: Python 3.12+ with Flask
- **Frontend**: Bootstrap 5 with Font Awesome icons
- **LDAP Client**: ldap3 library for robust LDAP operations
- **Authentication**: Session-based authentication with LDAP bind
- **Security**: Environment variable configuration, no hardcoded passwords

## Quick Start

1. **Set up environment variables**:
   ```bash
   export LDAP_ADMIN_PASSWORD="your_admin_password"
   ```
   Or use the interactive setup script:
   ```bash
   ./setup_env.sh
   ```

2. **Install dependencies**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Access the portal**:
   - **URL**: http://localhost:5000
   - **Admin Login**: Username `admin` + your LDAP admin password
   - **User Login**: Any valid LDAP user credentials

## Production Deployment

For production deployment with systemd service, Nginx proxy, and complete LDAP server setup, see the comprehensive [SETUP.md](SETUP.md) guide.

## Configuration

The application supports environment-based configuration:

| Environment Variable | Default Value | Description |
|---------------------|---------------|-------------|
| `LDAP_SERVER` | `192.168.1.1` | LDAP server hostname/IP |
| `LDAP_PORT` | `389` | LDAP server port |
| `LDAP_BASE_DN` | `dc=mylab,dc=lan` | LDAP base DN |
| `LDAP_ADMIN_DN` | `cn=admin,dc=mylab,dc=lan` | LDAP admin DN |
| `LDAP_ADMIN_PASSWORD` | **(Required)** | LDAP admin password |
| `DEBUG_MODE` | `False` | Enable debug logging (set to `true` only for development) |

## Security Features

- ✅ **No hardcoded passwords** - All credentials via environment variables
- ✅ **Secure session management** - Flask-Session with filesystem storage
- ✅ **LDAP authentication** - Direct LDAP bind for user verification
- ✅ **Multi-tier access control** - Super admin vs Group admin privileges
- ✅ **Input validation** - Form validation and LDAP injection prevention
- ✅ **Secure configuration** - Environment-based sensitive data handling

## File Structure

```
pythonldapman/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── setup_env.sh          # Environment setup script
├── INSTALLATION.md       # Complete installation guide
├── static/               # Frontend assets (CSS, JS, images)
├── templates/            # Jinja2 HTML templates
└── config/              # Configuration files (created during setup)
```

## License

This project is developed for LDAP administration and user self-service purposes.

## Support

For installation and configuration issues, refer to [SETUP.md](SETUP.md) or check the application logs.
   ```bash
   python app.py
   ```

2. Open your web browser and go to: `http://localhost:5000`

3. Login credentials:
   - **Admin**: Username `admin` with your admin password
   - **Users**: Use their LDAP username and password

## User Guide

### For Regular Users
1. Login with your LDAP username and password
2. Navigate to "My Profile" to update your information
3. Use "Change Password" to update your password
4. All changes are saved directly to the LDAP directory

### For Administrators
1. Login with username `admin` and your admin password
2. Access the "Admin Panel" from the navigation menu
3. Manage users through "Manage Users"
4. Create new users with "Add New User"
5. Edit any LDAP entry with the generic entry editor
6. Delete entries with confirmation dialogs

## Security Features

- **LDAP Authentication**: All logins verified against LDAP server
- **Session Management**: Secure session handling with Flask-Session
- **Password Hashing**: SSHA password hashing for new passwords
- **Access Control**: Role-based access with user/admin separation
- **Input Validation**: Form validation and sanitization

## LDAP Schema Support

The application supports standard LDAP object classes:

### User Accounts (inetOrgPerson)
- uid (username)
- cn (common name)
- sn (surname)
- givenName (first name)
- mail (email)
- telephoneNumber (phone)
- userPassword (password)
- description

### Groups (groupOfNames)
- cn (group name)
- description
- member (group members)

## File Structure

```
pythonldapman/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/            # Jinja2 templates
│   ├── base.html         # Base template with Bootstrap
│   ├── login.html        # Login page
│   ├── dashboard.html    # User dashboard
│   ├── profile.html      # User profile editor
│   ├── change_password.html # Password change form
│   └── admin/           # Admin templates
│       ├── panel.html   # Admin dashboard
│       ├── users.html   # User management
│       ├── groups.html  # Group management
│       ├── add_user.html # Add user form
│       └── edit_entry.html # Generic entry editor
└── static/              # Static files (if needed)
```

## Customization

### LDAP Configuration
Edit the configuration variables in `app.py`:

```python
LDAP_SERVER = '192.168.1.1'
LDAP_PORT = 389
LDAP_BASE_DN = 'dc=mylab,dc=lan'
LDAP_ADMIN_DN = 'cn=admin,dc=mylab,dc=com'
```

### UI Customization
- Templates use Bootstrap 5 classes for easy customization
- Modify `templates/base.html` for global layout changes
- Add custom CSS in the `static/` directory

## Error Handling

The application includes comprehensive error handling:
- LDAP connection errors
- Authentication failures
- Invalid form data
- Missing entries
- Permission denied scenarios

## Development

To contribute or modify the application:

1. The main application logic is in `app.py`
2. Templates are in the `templates/` directory
3. Use the Flask development server for testing
4. All LDAP operations go through the `LDAPManager` class

## License

This project is open-source and available for modification and distribution.

## Support

For issues or questions:
1. Check the LDAP server connectivity
2. Verify credentials and DN configuration
3. Review Flask application logs
4. Test LDAP operations manually with ldapsearch
