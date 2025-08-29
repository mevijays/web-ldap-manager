#!/usr/bin/env python3
"""
LDAP Management Portal
A Flask-based web application for LDAP administration and user self-service
"""

import os
import secrets
import base64
import mimetypes
import time
import hashlib
from datetime import datetime
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_session import Session
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
from ldap3.core.exceptions import LDAPException, LDAPBindError
from werkzeug.security import check_password_hash, generate_password_hash
import hashlib
import base64
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
Session(app)

# Template filters for shadow password management
@app.template_filter('timestamp')
def timestamp_filter(unix_days):
    """Convert Unix days since epoch to datetime object"""
    try:
        # Unix epoch is January 1, 1970
        # Convert days to seconds and add to epoch
        unix_timestamp = int(unix_days) * 86400  # Convert days to seconds
        return datetime.fromtimestamp(unix_timestamp)
    except (ValueError, TypeError):
        return datetime.now()

@app.template_filter('strftime')
def strftime_filter(dt, fmt='%B %d, %Y'):
    """Format datetime object using strftime"""
    try:
        if isinstance(dt, datetime):
            return dt.strftime(fmt)
        return str(dt)
    except (ValueError, TypeError, AttributeError):
        return str(dt)

@app.template_global()
def current_timestamp():
    """Get current timestamp for template calculations"""
    import time
    return int(time.time())

@app.template_global()
def unix_days_from_epoch():
    """Get current days since Unix epoch for shadow calculations"""
    import time
    return int(time.time() // 86400)

def process_photo(photo_file):
    """Process uploaded photo for LDAP storage"""
    try:
        from PIL import Image
        import io
        
        # Check file size (max 2MB)
        photo_file.seek(0, 2)  # Seek to end
        file_size = photo_file.tell()
        photo_file.seek(0)  # Reset to beginning
        
        if file_size > 2 * 1024 * 1024:  # 2MB limit
            return None
            
        # Open and process image
        image = Image.open(photo_file)
        
        # Convert to RGB if necessary
        if image.mode in ('RGBA', 'P'):
            image = image.convert('RGB')
        
        # Resize if too large (max 300x300)
        max_size = (300, 300)
        image.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        # Save as JPEG
        output = io.BytesIO()
        image.save(output, format='JPEG', quality=85, optimize=True)
        photo_data = output.getvalue()
        
        return photo_data
        
    except Exception as e:
        print(f"Error processing photo: {e}")
        return None

# LDAP Configuration
LDAP_SERVER = os.getenv('LDAP_SERVER', '192.168.1.1')
LDAP_PORT = int(os.getenv('LDAP_PORT', '389'))
LDAP_BASE_DN = os.getenv('LDAP_BASE_DN', 'dc=mylab,dc=lan')
LDAP_ADMIN_DN = os.getenv('LDAP_ADMIN_DN', 'cn=admin,dc=mylab,dc=lan')
LDAP_ADMIN_PASSWORD = os.getenv('LDAP_ADMIN_PASSWORD')
LDAP_PEOPLE_OU = f"ou=People,{LDAP_BASE_DN}"
LDAP_GROUPS_OU = f"ou=Groups,{LDAP_BASE_DN}"

# Production configuration - disable debug output
DEBUG_MODE = os.getenv('DEBUG_MODE', 'False').lower() == 'true'

# Configure basic logging for production
import logging
if not DEBUG_MODE:
    # Only log warnings and above in production
    logging.basicConfig(level=logging.WARNING)
    app.logger.setLevel(logging.WARNING)

# Validate required environment variables
if not LDAP_ADMIN_PASSWORD:
    raise ValueError("LDAP_ADMIN_PASSWORD environment variable is required")

class LDAPManager:
    def __init__(self):
        self.server = Server(LDAP_SERVER, port=LDAP_PORT, get_info=ALL)
        self.last_error = ""
    
    def is_user_in_admin_group(self, user_dn):
        """Check if user is a member of the admins group"""
        try:
            admins_group_dn = f'cn=admins,{LDAP_GROUPS_OU}'
            if DEBUG_MODE:
                print(f"DEBUG: Checking if {user_dn} is in admin group {admins_group_dn}")
            
            # Use admin credentials to check group membership
            conn = Connection(self.server, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD, auto_bind=True)
            
            # Search for the admins group
            conn.search(admins_group_dn, '(objectClass=*)', attributes=['member'])
            if conn.entries:
                group_entry = conn.entries[0]
                members = group_entry.member.values if hasattr(group_entry, 'member') else []
                if DEBUG_MODE:
                    print(f"DEBUG: Admin group members: {members}")
                    print(f"DEBUG: Is {user_dn} in admin group: {user_dn in members}")
                conn.unbind()
                return user_dn in members
            else:
                if DEBUG_MODE:
                    print("DEBUG: Admin group not found")
            
            conn.unbind()
            return False
        except Exception as e:
            if DEBUG_MODE:
                print(f"DEBUG: Error checking admin group membership: {e}")
            return False

    def authenticate_user(self, username, password):
        """Authenticate user against LDAP"""
        try:
            # Check if it's admin login
            if username == 'admin':
                user_dn = LDAP_ADMIN_DN
                if DEBUG_MODE:
                    print(f"DEBUG: Attempting admin login with DN: {user_dn}")
                
                conn = Connection(self.server, user_dn, password, auto_bind=True)
                if DEBUG_MODE:
                    print(f"DEBUG: LDAP connection successful for {username}")
                conn.unbind()
                
                return {
                    'dn': user_dn,
                    'username': username,
                    'is_admin': True,
                    'is_super_admin': True,  # cn=admin is super admin (no profile editing)
                    'attributes': {'cn': ['admin']}
                }
            else:
                # Search for user in People OU
                user_dn = f'uid={username},{LDAP_PEOPLE_OU}'
                if DEBUG_MODE:
                    print(f"DEBUG: Attempting user login with DN: {user_dn}")
                
                conn = Connection(self.server, user_dn, password, auto_bind=True)
                if DEBUG_MODE:
                    print(f"DEBUG: LDAP connection successful for {username}")
                
                # Search for user attributes
                conn.search(user_dn, '(objectClass=*)', attributes=['*'])
                if conn.entries:
                    entry = conn.entries[0]
                    user_attributes = dict(entry.entry_attributes_as_dict)
                    
                    # Check if account is locked
                    if self.is_user_locked(user_attributes):
                        conn.unbind()
                        return {'locked': True, 'message': 'Account is locked. Please contact administrator.'}
                    
                    # Check if user is in admins group
                    is_in_admin_group = self.is_user_in_admin_group(user_dn)
                    
                    conn.unbind()
                    return {
                        'dn': str(entry.entry_dn),
                        'username': username,
                        'is_admin': is_in_admin_group,
                        'is_super_admin': False,  # Regular users/group admins can edit profiles
                        'attributes': user_attributes
                    }
            
            return None
        except LDAPBindError as e:
            if DEBUG_MODE:
                print(f"DEBUG: LDAP Bind Error for {username}: {e}")
            return None
        except Exception as e:
            print(f"LDAP Authentication Error: {e}")
            return None
    
    def get_connection(self, bind_dn=None, password=None):
        """Get LDAP connection"""
        try:
            if bind_dn and password:
                if DEBUG_MODE:
                    print(f"DEBUG: Using provided credentials: {bind_dn}")
                conn = Connection(self.server, bind_dn, password, auto_bind=True)
            else:
                # For admin operations, use admin credentials from environment or session
                admin_password = os.getenv('LDAP_ADMIN_PASSWORD')
                if admin_password:
                    if DEBUG_MODE:
                        print(f"DEBUG: Using admin credentials from environment")
                    conn = Connection(self.server, LDAP_ADMIN_DN, admin_password, auto_bind=True)
                else:
                    if DEBUG_MODE:
                        print(f"DEBUG: Using session credentials")
                    # Fallback to session credentials
                    conn = Connection(self.server, session.get('user_dn'), session.get('password'), auto_bind=True)
            return conn
        except Exception as e:
            print(f"LDAP Connection Error: {e}")
            return None
    
    def search_entries(self, base_dn, search_filter='(objectClass=*)', attributes=None):
        """Search LDAP entries"""
        conn = self.get_connection()
        if not conn:
            return []
        
        try:
            conn.search(base_dn, search_filter, attributes=attributes or ['*'])
            entries = []
            for entry in conn.entries:
                entries.append({
                    'dn': str(entry.entry_dn),
                    'attributes': dict(entry.entry_attributes_as_dict)
                })
            conn.unbind()
            return entries
        except Exception as e:
            print(f"LDAP Search Error: {e}")
            return []
    
    def modify_entry(self, dn, changes):
        """Modify an LDAP entry with detailed logging"""
        try:
            if DEBUG_MODE:
                print(f"DEBUG: Attempting to modify entry: {dn}")
                print(f"DEBUG: Changes: {changes}")
            
            conn = self.get_connection()
            if not conn:
                if DEBUG_MODE:
                    print("DEBUG: No LDAP connection available")
                return False
            
            result = conn.modify(dn, changes)
            if DEBUG_MODE:
                print(f"DEBUG: Modify result: {result}")
                print(f"DEBUG: LDAP result: {conn.result}")
            
            conn.unbind()
            
            if result:
                if DEBUG_MODE:
                    print("DEBUG: Entry modified successfully")
                return True
            else:
                if DEBUG_MODE:
                    print(f"DEBUG: Modify failed - Result: {conn.result}")
                return False
        except Exception as e:
            if DEBUG_MODE:
                print(f"DEBUG: Exception during modify: {str(e)}")
            return False
    
    def add_entry(self, entry_dn, object_classes, attributes):
        """Add new LDAP entry"""
        conn = self.get_connection()
        if not conn:
            self.last_error = "Failed to establish LDAP connection"
            return False
        
        try:
            conn.add(entry_dn, object_classes, attributes)
            success = conn.result['result'] == 0
            if not success:
                self.last_error = f"LDAP Add Error: {conn.result.get('description', 'Unknown error')}"
                print(f"LDAP Add Error: {conn.result}")
            conn.unbind()
            return success
        except Exception as e:
            self.last_error = f"LDAP Add Exception: {e}"
            print(f"LDAP Add Error: {e}")
            return False
    
    def delete_entry(self, entry_dn):
        """Delete LDAP entry"""
        conn = self.get_connection()
        if not conn:
            return False
        
        try:
            conn.delete(entry_dn)
            success = conn.result['result'] == 0
            conn.unbind()
            return success
        except Exception as e:
            print(f"LDAP Delete Error: {e}")
            return False
    
    def change_password(self, user_dn, new_password):
        """Change user password"""
        conn = self.get_connection()
        if not conn:
            return False
        
        try:
            # Create SSHA password hash
            password_hash = self.create_ssha_password(new_password)
            
            # For admin users, we might need to handle differently
            if 'cn=admin' in user_dn:
                # Admin password change - use userPassword attribute
                modifications = {'userPassword': [(MODIFY_REPLACE, [password_hash])]}
            else:
                # Regular user password change
                modifications = {'userPassword': [(MODIFY_REPLACE, [password_hash])]}
            
            conn.modify(user_dn, modifications)
            success = conn.result['result'] == 0
            conn.unbind()
            return success
        except Exception as e:
            print(f"Password Change Error: {e}")
            return False
    
    def create_ssha_password(self, password):
        """Create SSHA password hash"""
        salt = os.urandom(4)
        sha = hashlib.sha1(password.encode('utf-8'))
        sha.update(salt)
        digest = sha.digest()
        return '{SSHA}' + base64.b64encode(digest + salt).decode('utf-8')
    
    def get_next_uid_number(self):
        """Get next available UID number for POSIX accounts"""
        try:
            # Search for all posixAccount entries to find highest UID
            entries = self.search_entries(LDAP_BASE_DN, '(objectClass=posixAccount)', ['uidNumber'])
            
            max_uid = 1000  # Start from 1000 for user accounts
            for entry in entries:
                uid_number = entry.get('attributes', {}).get('uidNumber')
                if uid_number and len(uid_number) > 0:
                    try:
                        current_uid = int(uid_number[0])
                        if current_uid >= 1000:  # Only consider user UIDs (>= 1000)
                            max_uid = max(max_uid, current_uid)
                    except (ValueError, IndexError):
                        continue
            
            return max_uid + 1
        except Exception as e:
            print(f"Error getting next UID: {e}")
            return 1000  # Default fallback
    
    def get_next_gid_number(self):
        """Get next available GID number for POSIX groups"""
        try:
            # Search for all posixGroup and posixAccount entries to find highest GID
            group_entries = self.search_entries(LDAP_BASE_DN, '(objectClass=posixGroup)', ['gidNumber'])
            account_entries = self.search_entries(LDAP_BASE_DN, '(objectClass=posixAccount)', ['gidNumber'])
            
            all_entries = group_entries + account_entries
            max_gid = 1000  # Start from 1000 for user groups
            
            for entry in all_entries:
                gid_number = entry.get('attributes', {}).get('gidNumber')
                if gid_number and len(gid_number) > 0:
                    try:
                        current_gid = int(gid_number[0])
                        if current_gid >= 1000:  # Only consider user GIDs (>= 1000)
                            max_gid = max(max_gid, current_gid)
                    except (ValueError, IndexError):
                        continue
            
            return max_gid + 1
        except Exception as e:
            print(f"Error getting next GID: {e}")
            return 1000  # Default fallback

    def get_ldap_statistics(self):
        """Get comprehensive LDAP server statistics"""
        try:
            stats = {
                'total_users': 0,
                'total_groups': 0,
                'posix_users': 0,
                'standard_users': 0,
                'admin_users': 0,
                'locked_users': 0,
                'expiring_passwords': [],
                'error': None
            }
            
            # Get all users
            try:
                all_users = self.search_entries(LDAP_PEOPLE_OU, '(objectClass=person)', 
                                              ['uid', 'cn', 'objectClass', 'uidNumber', 'shadowExpire', 
                                               'shadowLastChange', 'shadowMax', 'loginShell', 'userPassword'])
                stats['total_users'] = len(all_users) if all_users else 0
            except Exception as e:
                print(f"Error getting users for statistics: {e}")
                all_users = []
            
            current_days = int((datetime.now() - datetime(1970, 1, 1)).days)
            
            for user in all_users:
                attrs = user.get('attributes', {})
                uid = attrs.get('uid', ['Unknown'])[0] if attrs.get('uid') else 'Unknown'
                cn = attrs.get('cn', ['Unknown'])[0] if attrs.get('cn') else 'Unknown'
                
                # Check if POSIX user
                if attrs.get('uidNumber'):
                    stats['posix_users'] += 1
                    
                    # Check for locked users (no shell access)
                    login_shell = attrs.get('loginShell', [''])[0] if attrs.get('loginShell') else ''
                    if login_shell in ['/sbin/nologin', '/bin/false', '']:
                        stats['locked_users'] += 1
                    
                    # Check password expiry
                    try:
                        shadow_expire_list = attrs.get('shadowExpire', [])
                        shadow_last_change_list = attrs.get('shadowLastChange', [])
                        shadow_max_list = attrs.get('shadowMax', ['90'])
                        
                        shadow_expire = shadow_expire_list[0] if shadow_expire_list else None
                        shadow_last_change = shadow_last_change_list[0] if shadow_last_change_list else None
                        shadow_max = shadow_max_list[0] if shadow_max_list else '90'
                        
                        days_until_expire = None
                        
                        if shadow_expire:
                            days_until_expire = int(shadow_expire) - current_days
                        elif shadow_last_change and shadow_max:
                            expire_days = int(shadow_last_change) + int(shadow_max)
                            days_until_expire = expire_days - current_days
                        
                        # Check if password expires within 7 days
                        if days_until_expire is not None and 0 <= days_until_expire <= 7:
                            stats['expiring_passwords'].append({
                                'uid': uid,
                                'cn': cn,
                                'days_remaining': days_until_expire,
                                'expired': days_until_expire < 0
                            })
                    except (ValueError, TypeError):
                        pass
                else:
                    stats['standard_users'] += 1
                
                # Check if admin user
                try:
                    admin_groups = ['cn=admins,ou=Groups,dc=mylab,dc=lan', 'cn=admin,ou=Groups,dc=mylab,dc=lan', 'cn=administrators,ou=Groups,dc=mylab,dc=lan']
                    user_groups = self.get_user_groups(user.get('dn', ''))
                    if user_groups and any(group.get('dn', '') in admin_groups for group in user_groups):
                        stats['admin_users'] += 1
                except Exception:
                    # Skip admin check if there's an error
                    pass
            
            # Get all groups
            try:
                all_groups = self.search_entries(LDAP_GROUPS_OU, '(|(objectClass=groupOfNames)(objectClass=posixGroup))', 
                                               ['cn', 'objectClass'])
                stats['total_groups'] = len(all_groups) if all_groups else 0
            except Exception as e:
                print(f"Error getting groups for statistics: {e}")
                stats['total_groups'] = 0
            
            return stats
            
        except Exception as e:
            return {
                'total_users': 0,
                'total_groups': 0,
                'posix_users': 0,
                'standard_users': 0,
                'admin_users': 0,
                'locked_users': 0,
                'expiring_passwords': [],
                'error': str(e)
            }

    def get_user_groups(self, user_dn):
        """Get groups that a user belongs to"""
        try:
            # Search for groups where user is a member (both member and memberUid)
            uid = user_dn.split(',')[0].split('=')[1] if 'uid=' in user_dn else ''
            
            groups = []
            
            # Search by DN (member attribute)
            member_groups = self.search_entries(LDAP_GROUPS_OU, f'(member={user_dn})', ['cn', 'objectClass'])
            groups.extend(member_groups)
            
            # Search by UID (memberUid attribute) for POSIX groups
            if uid:
                memberuid_groups = self.search_entries(LDAP_GROUPS_OU, f'(memberUid={uid})', ['cn', 'objectClass'])
                groups.extend(memberuid_groups)
            
            return groups
        except Exception as e:
            print(f"Error getting user groups: {e}")
            return []
    
    def lock_user_account(self, user_dn):
        """Lock user account - improved method for both standard and POSIX users"""
        try:
            # First, get user information to determine account type
            user_info = self.search_entries(user_dn)
            if not user_info:
                return False
            
            user_attributes = user_info[0].get('attributes', {})
            is_posix_account = 'uidNumber' in user_attributes
            
            if DEBUG_MODE:
                print(f"DEBUG: Locking user {user_dn}, POSIX: {is_posix_account}")
            
            # Method 1: Try shadowFlag for shadowAccount users (both standard and POSIX can have this)
            try:
                modifications = {
                    'shadowFlag': [(MODIFY_REPLACE, ['1'])]  # 1 = account locked
                }
                
                if self.modify_entry(user_dn, modifications):
                    # Also set description for visual indication
                    desc_modifications = {
                        'description': [(MODIFY_REPLACE, ['ACCOUNT_LOCKED'])]
                    }
                    self.modify_entry(user_dn, desc_modifications)  # Don't fail if this doesn't work
                    return True
            except Exception as e:
                if DEBUG_MODE:
                    print(f"DEBUG: shadowFlag method failed: {e}")
            
            # Method 2: For POSIX accounts, disable login shell
            if is_posix_account:
                try:
                    current_shell = user_attributes.get('loginShell', ['/bin/bash'])[0]
                    # Store original shell in description and set to invalid shell
                    modifications = {
                        'loginShell': [(MODIFY_REPLACE, ['/bin/false'])],
                        'description': [(MODIFY_REPLACE, [f'ACCOUNT_LOCKED:SHELL:{current_shell}'])]
                    }
                    
                    if self.modify_entry(user_dn, modifications):
                        return True
                except Exception as e:
                    if DEBUG_MODE:
                        print(f"DEBUG: POSIX shell locking failed: {e}")
            
            # Method 3: Fallback - Set description to indicate locked status (for display only)
            modifications = {
                'description': [(MODIFY_REPLACE, ['ACCOUNT_LOCKED'])]
            }
            return self.modify_entry(user_dn, modifications)
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"DEBUG: Error locking user account: {e}")
            return False
    
    def unlock_user_account(self, user_dn):
        """Unlock user account - improved method for both standard and POSIX users"""
        try:
            # First, get user information to determine unlock method
            user_info = self.search_entries(user_dn)
            if not user_info:
                return False
            
            user_attributes = user_info[0].get('attributes', {})
            description = user_attributes.get('description', [''])[0] if user_attributes.get('description') else ''
            
            if DEBUG_MODE:
                print(f"DEBUG: Unlocking user {user_dn}, description: {description}")
            
            # Method 1: Remove shadowFlag if present
            try:
                modifications = {
                    'shadowFlag': [(MODIFY_DELETE, [])]
                }
                
                if self.modify_entry(user_dn, modifications):
                    # Also clear description if it's just ACCOUNT_LOCKED
                    if description == 'ACCOUNT_LOCKED':
                        desc_modifications = {
                            'description': [(MODIFY_DELETE, [])]
                        }
                        self.modify_entry(user_dn, desc_modifications)
                    return True
            except Exception as e:
                if DEBUG_MODE:
                    print(f"DEBUG: shadowFlag removal failed: {e}")
            
            # Method 2: Restore original shell for POSIX accounts
            if 'ACCOUNT_LOCKED:SHELL:' in description:
                try:
                    # Extract original shell from description
                    original_shell = description.split('ACCOUNT_LOCKED:SHELL:')[1]
                    modifications = {
                        'loginShell': [(MODIFY_REPLACE, [original_shell])],
                        'description': [(MODIFY_DELETE, [])]
                    }
                    
                    if self.modify_entry(user_dn, modifications):
                        return True
                except Exception as e:
                    if DEBUG_MODE:
                        print(f"DEBUG: POSIX shell restore failed: {e}")
                    # If restore fails, at least set to a working shell
                    try:
                        modifications = {
                            'loginShell': [(MODIFY_REPLACE, ['/bin/bash'])],
                            'description': [(MODIFY_DELETE, [])]
                        }
                        if self.modify_entry(user_dn, modifications):
                            return True
                    except:
                        pass
            
            # Method 3: Fallback - Remove locked description
            if 'ACCOUNT_LOCKED' in description:
                modifications = {
                    'description': [(MODIFY_DELETE, [])]
                }
                return self.modify_entry(user_dn, modifications)
            
            return True  # Account wasn't locked anyway
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"DEBUG: Error unlocking user account: {e}")
            return False
    
    def is_user_locked(self, user_attributes):
        """Check if user account is locked - improved detection for all locking methods"""
        try:
            # Method 1: Check shadowFlag
            shadow_flag = user_attributes.get('shadowFlag', [])
            if shadow_flag and shadow_flag[0] == '1':
                return True
            
            # Method 2: Check description for lock status
            description = user_attributes.get('description', [])
            if description and 'ACCOUNT_LOCKED' in description[0]:
                return True
            
            # Method 3: Check if POSIX user has disabled shell (login shell is /bin/false)
            login_shell = user_attributes.get('loginShell', [])
            if login_shell and login_shell[0] == '/bin/false' and description and 'ACCOUNT_LOCKED:SHELL:' in description[0]:
                return True
            
            return False
        except Exception:
            return False
    
    def set_password_expiry(self, user_dn, days_from_now=90):
        """Set password expiry date"""
        try:
            from datetime import datetime, timedelta
            
            # Calculate expiry date (days since Unix epoch)
            expiry_date = datetime.now() + timedelta(days=days_from_now)
            days_since_epoch = int((expiry_date - datetime(1970, 1, 1)).days)
            
            modifications = {
                'shadowExpire': [(MODIFY_REPLACE, [str(days_since_epoch)])]
            }
            return self.modify_entry(user_dn, modifications)
        except Exception as e:
            print(f"Error setting password expiry: {e}")
            return False

# Initialize LDAP manager
ldap_manager = LDAPManager()

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_dn' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin', False):
            flash('Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Home page"""
    if 'user_dn' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_info = ldap_manager.authenticate_user(username, password)
        if user_info:
            # Check if account is locked
            if user_info.get('locked'):
                flash(user_info.get('message', 'Account is locked. Please contact administrator.'), 'error')
                return render_template('login.html')
            
            session['user_dn'] = user_info['dn']
            session['username'] = user_info['username']
            session['is_admin'] = user_info['is_admin']
            session['is_super_admin'] = user_info['is_super_admin']
            session['password'] = password  # Store for LDAP operations
            session['user_attributes'] = user_info['attributes']
            
            # Different welcome messages for different admin types
            if user_info['is_super_admin']:
                flash(f'Welcome, Super Administrator {username}!', 'success')
            elif user_info['is_admin']:
                flash(f'Welcome, Administrator {username}!', 'success')
            else:
                flash(f'Welcome, {username}!', 'success')
                
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with LDAP statistics for admin users"""
    stats = None
    if session.get('is_admin', False):
        # Get LDAP statistics for admin users
        stats = ldap_manager.get_ldap_statistics()
    
    return render_template('dashboard.html', 
                         username=session.get('username'),
                         is_admin=session.get('is_admin', False),
                         stats=stats)

@app.route('/users')
@login_required
def user_search():
    """User search and directory"""
    search_query = request.args.get('q', '')
    users = []
    
    if search_query:
        # Search for users by username, name, or email
        search_filter = f'(&(objectClass=person)(|(uid=*{search_query}*)(cn=*{search_query}*)(mail=*{search_query}*)))'
        users = ldap_manager.search_entries(LDAP_PEOPLE_OU, search_filter)
    else:
        # Show all users if no search query
        users = ldap_manager.search_entries(LDAP_PEOPLE_OU, '(objectClass=person)')
    
    return render_template('users.html', users=users, search_query=search_query)

@app.route('/user/<username>')
@login_required
def user_profile(username):
    """View another user's profile (read-only)"""
    user_dn = f'uid={username},{LDAP_PEOPLE_OU}'
    entries = ldap_manager.search_entries(user_dn)
    user_data = entries[0] if entries else None
    
    if not user_data:
        flash(f'User {username} not found.', 'error')
        return redirect(url_for('user_search'))
    
    return render_template('user_profile.html', user_data=user_data)

@app.route('/user/<username>/photo')
def user_photo(username):
    """Serve user profile photo"""
    user_dn = f'uid={username},{LDAP_PEOPLE_OU}'
    entries = ldap_manager.search_entries(user_dn, attributes=['jpegPhoto'])
    
    if entries and 'jpegPhoto' in entries[0]['attributes'] and entries[0]['attributes']['jpegPhoto']:
        photo_data = entries[0]['attributes']['jpegPhoto'][0]
        if isinstance(photo_data, str):
            # If it's base64 encoded string, decode it
            try:
                photo_data = base64.b64decode(photo_data)
            except:
                pass
        return send_file(BytesIO(photo_data), mimetype='image/jpeg')
    else:
        # Return default avatar
        default_path = os.path.join(app.static_folder, 'img', 'default-avatar.png')
        if os.path.exists(default_path):
            return send_file(default_path, mimetype='image/png')
        else:
            return redirect(url_for('static', filename='img/default-avatar.png'))

@app.route('/upload_photo', methods=['POST'])
@login_required
def upload_photo():
    """Upload profile photo for current user"""
    # Prevent super admin from uploading photos
    if session.get('is_super_admin', False):
        flash('Photo upload not available for super admin accounts.', 'info')
        return redirect(url_for('profile'))
        
    if 'photo' not in request.files:
        flash('No photo file selected.', 'error')
        return redirect(url_for('profile'))
    
    file = request.files['photo']
    if file.filename == '':
        flash('No photo file selected.', 'error')
        return redirect(url_for('profile'))
    
    if not file.content_type.startswith('image/'):
        flash('Please upload a valid image file.', 'error')
        return redirect(url_for('profile'))
    
    try:
        # Read and process the image
        photo_data = file.read()
        
        # Resize image if PIL is available
        if PIL_AVAILABLE:
            image = Image.open(BytesIO(photo_data))
            # Resize to max 200x200 while maintaining aspect ratio
            image.thumbnail((200, 200), Image.Resampling.LANCZOS)
            # Convert to RGB if necessary
            if image.mode in ('RGBA', 'LA', 'P'):
                image = image.convert('RGB')
            # Save as JPEG
            buffer = BytesIO()
            image.save(buffer, format='JPEG', quality=85)
            photo_data = buffer.getvalue()
        
        # Update LDAP entry
        user_dn = session['user_dn']
        changes = {'jpegPhoto': [(MODIFY_REPLACE, [photo_data])]}
        
        if ldap_manager.modify_entry(user_dn, changes):
            flash('Profile photo updated successfully!', 'success')
        else:
            flash('Failed to update profile photo.', 'error')
            
    except Exception as e:
        flash(f'Error processing photo: {str(e)}', 'error')
    
    return redirect(url_for('profile'))

@app.route('/delete_photo', methods=['POST'])
@login_required
def delete_photo():
    """Delete profile photo for current user"""
    # Prevent super admin from deleting photos
    if session.get('is_super_admin', False):
        flash('Photo management not available for super admin accounts.', 'info')
        return redirect(url_for('profile'))
        
    user_dn = session['user_dn']
    changes = {'jpegPhoto': [(MODIFY_DELETE, [])]}
    
    if ldap_manager.modify_entry(user_dn, changes):
        flash('Profile photo deleted successfully!', 'success')
    else:
        flash('Failed to delete profile photo.', 'error')
    
    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    """User profile management"""
    user_dn = session.get('user_dn')
    
    # Handle admin user specially
    if session.get('is_admin', False):
        # Admin doesn't have a profile in People OU, create a mock profile
        user_data = {
            'dn': user_dn,
            'attributes': {
                'uid': ['admin'],
                'cn': ['Administrator'],
                'sn': ['Administrator'],
                'givenName': ['System'],
                'mail': ['admin@mylab.lan'],
                'displayName': ['System Administrator'],
                'description': ['LDAP System Administrator']
            }
        }
        password_info = None
    else:
        # Get current user attributes for regular users - include shadow attributes
        entries = ldap_manager.search_entries(user_dn, attributes=['*', 'shadowExpire', 'shadowLastChange', 'shadowMax', 'shadowMin'])
        user_data = entries[0] if entries else {
            'dn': user_dn,
            'attributes': {}
        }
        
        # Calculate password expiry information for POSIX accounts
        password_info = None
        attrs = user_data['attributes']
        
        # Check if this is a POSIX user with shadow attributes
        if attrs.get('uidNumber') and (attrs.get('shadowExpire') or attrs.get('shadowLastChange')):
            try:
                current_days = int((datetime.now() - datetime(1970, 1, 1)).days)
                
                # Get shadow attributes
                shadow_expire = attrs.get('shadowExpire', [None])[0]
                shadow_last_change = attrs.get('shadowLastChange', [None])[0]
                shadow_max = attrs.get('shadowMax', ['90'])[0]  # Default 90 days
                
                # Calculate days since password was last changed
                days_since_change = 0
                if shadow_last_change:
                    days_since_change = current_days - int(shadow_last_change)
                
                # Calculate password expiry
                if shadow_expire:
                    # Explicit expiry date set
                    days_until_expire = int(shadow_expire) - current_days
                elif shadow_last_change and shadow_max:
                    # Calculate based on last change + max age
                    expire_days = int(shadow_last_change) + int(shadow_max)
                    days_until_expire = expire_days - current_days
                else:
                    # Default: assume 90 days from last change or account creation
                    if shadow_last_change:
                        expire_days = int(shadow_last_change) + 90
                    else:
                        expire_days = current_days + 90  # New account, expires in 90 days
                    days_until_expire = expire_days - current_days
                
                password_info = {
                    'days_until_expire': days_until_expire,
                    'days_since_change': days_since_change,
                    'password_expired': days_until_expire < 0,
                    'password_expires_soon': 0 <= days_until_expire <= 7,
                    'shadow_max': int(shadow_max) if shadow_max else 90
                }
            except (ValueError, IndexError, TypeError) as e:
                if DEBUG_MODE:
                    print(f"DEBUG: Error calculating password info: {e}")
                # Provide default info for POSIX users even if shadow attributes are incomplete
                if attrs.get('uidNumber'):
                    password_info = {
                        'days_until_expire': 90,
                        'days_since_change': 0,
                        'password_expired': False,
                        'password_expires_soon': False,
                        'shadow_max': 90
                    }
    
    return render_template('profile.html', user_data=user_data, password_info=password_info)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Verify current password
        user_info = ldap_manager.authenticate_user(session.get('username'), current_password)
        if not user_info:
            flash('Current password is incorrect.', 'error')
            return render_template('change_password.html')
        
        # Check password confirmation
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html')
        
        # Check if admin is trying to change password
        if session.get('is_admin', False):
            # Allow admin password change but with warnings
            flash('Admin password changed. Please ensure you remember the new password as recovery may be difficult.', 'warning')
            
            # Try to change admin password
            if ldap_manager.change_password(session.get('user_dn'), new_password):
                session['password'] = new_password  # Update session
                flash('Admin password changed successfully. Please note this change for your records.', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Failed to change admin password. Please use LDAP admin tools instead.', 'error')
                return render_template('change_password.html')
        
        # Change password for regular users
        if ldap_manager.change_password(session.get('user_dn'), new_password):
            session['password'] = new_password  # Update session
            flash('Password changed successfully.', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Failed to change password.', 'error')
    
    return render_template('change_password.html')

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    user_dn = session.get('user_dn')
    
    # Check if super admin is trying to update profile
    if session.get('is_super_admin', False):
        flash('Super admin profile updates are not supported. Super admin is a system account.', 'info')
        return redirect(url_for('profile'))
    
    # Get form data for regular users and group admins
    modifications = {}
    
    # Common Name (Full Name)
    if 'cn' in request.form and request.form['cn'].strip():
        modifications['cn'] = [(MODIFY_REPLACE, [request.form['cn'].strip()])]
    
    # Display Name
    if 'displayName' in request.form and request.form['displayName'].strip():
        modifications['displayName'] = [(MODIFY_REPLACE, [request.form['displayName'].strip()])]
    
    # Email
    if 'mail' in request.form and request.form['mail'].strip():
        modifications['mail'] = [(MODIFY_REPLACE, [request.form['mail'].strip()])]
    
    # Phone/Mobile Number
    if 'telephoneNumber' in request.form and request.form['telephoneNumber'].strip():
        modifications['telephoneNumber'] = [(MODIFY_REPLACE, [request.form['telephoneNumber'].strip()])]
    
    # Mobile (alternative mobile field)
    if 'mobile' in request.form and request.form['mobile'].strip():
        modifications['mobile'] = [(MODIFY_REPLACE, [request.form['mobile'].strip()])]
    
    # Description
    if 'description' in request.form and request.form['description'].strip():
        modifications['description'] = [(MODIFY_REPLACE, [request.form['description'].strip()])]
    
    # Job Title
    if 'title' in request.form and request.form['title'].strip():
        modifications['title'] = [(MODIFY_REPLACE, [request.form['title'].strip()])]
    
    # Department
    if 'department' in request.form and request.form['department'].strip():
        modifications['department'] = [(MODIFY_REPLACE, [request.form['department'].strip()])]
    
    # Organization
    if 'o' in request.form and request.form['o'].strip():
        modifications['o'] = [(MODIFY_REPLACE, [request.form['o'].strip()])]
    
    # POSIX Account attributes (only if user has POSIX account)
    user_entries = ldap_manager.search_entries(user_dn)
    if user_entries:
        user_attributes = user_entries[0].get('attributes', {})
        has_posix = 'uidNumber' in user_attributes
        
        if has_posix:
            # Home Directory
            if 'homeDirectory' in request.form and request.form['homeDirectory'].strip():
                modifications['homeDirectory'] = [(MODIFY_REPLACE, [request.form['homeDirectory'].strip()])]
            
            # Login Shell
            if 'loginShell' in request.form and request.form['loginShell'].strip():
                modifications['loginShell'] = [(MODIFY_REPLACE, [request.form['loginShell'].strip()])]
    
    if modifications:
        if ldap_manager.modify_entry(user_dn, modifications):
            flash('Profile updated successfully.', 'success')
            # Update session attributes to reflect changes
            user_entries = ldap_manager.search_entries(user_dn)
            if user_entries:
                session['user_attributes'] = user_entries[0]['attributes']
        else:
            flash('Failed to update profile.', 'error')
    else:
        flash('No changes were made to your profile.', 'info')
    
    return redirect(url_for('profile'))

# Admin routes
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    """Admin panel"""
    return render_template('admin/panel.html')

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """Manage users"""
    users = ldap_manager.search_entries(LDAP_PEOPLE_OU, '(objectClass=person)')
    return render_template('admin/users.html', users=users)

@app.route('/admin/groups')
@login_required
@admin_required
def admin_groups():
    """Manage groups"""
    # Search for both groupOfNames and posixGroup entries
    groupofnames_groups = ldap_manager.search_entries(LDAP_GROUPS_OU, '(objectClass=groupOfNames)')
    posix_groups = ldap_manager.search_entries(LDAP_GROUPS_OU, '(objectClass=posixGroup)')
    
    # Combine and deduplicate groups (in case some groups have both object classes)
    all_groups = []
    seen_dns = set()
    
    for group in groupofnames_groups + posix_groups:
        if group['dn'] not in seen_dns:
            all_groups.append(group)
            seen_dns.add(group['dn'])
    
    return render_template('admin/groups.html', groups=all_groups)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_user():
    """Add new user"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form.get('phone', '')
        title = request.form.get('title', '')
        description = request.form.get('description', '')
        home_directory = request.form.get('home_directory', '')
        login_shell = request.form.get('login_shell', '')
        uid_number = request.form.get('uid_number', '')
        gid_number = request.form.get('gid_number', '')
        password_expiry_days = request.form.get('password_expiry_days', '90')
        
        user_dn = f'uid={username},{LDAP_PEOPLE_OU}'
        
        attributes = {
            'uid': username,
            'cn': f'{first_name} {last_name}',
            'sn': last_name,
            'givenName': first_name,
            'userPassword': ldap_manager.create_ssha_password(password),
            'mail': email
        }
        
        # Add optional attributes if provided
        if phone.strip():
            attributes['telephoneNumber'] = phone.strip()
        if title.strip():
            attributes['title'] = title.strip()
        if description.strip():
            attributes['description'] = description.strip()
        
        # Determine object classes
        object_classes = ['inetOrgPerson', 'organizationalPerson', 'person', 'top']
        
        # Add POSIX account support if POSIX fields are provided
        if home_directory.strip() or login_shell.strip() or uid_number.strip() or gid_number.strip():
            object_classes.extend(['posixAccount', 'shadowAccount'])
            
            # Set default values for required POSIX attributes
            attributes['homeDirectory'] = home_directory.strip() or f'/home/{username}'
            attributes['loginShell'] = login_shell.strip() or '/bin/bash'
            attributes['uidNumber'] = uid_number.strip() or str(ldap_manager.get_next_uid_number())
            attributes['gidNumber'] = gid_number.strip() or str(ldap_manager.get_next_gid_number())
            
            # Add shadow account attributes with defaults
            from datetime import datetime, timedelta
            
            current_days = int(time.time() / 86400)  # days since epoch
            attributes['shadowLastChange'] = str(current_days)
            attributes['shadowMin'] = '0'
            attributes['shadowMax'] = '99999'
            attributes['shadowWarning'] = '7'
            
            # Set password expiry if specified
            try:
                expiry_days = int(password_expiry_days)
                if expiry_days > 0:
                    expiry_date = datetime.now() + timedelta(days=expiry_days)
                    days_since_epoch = int((expiry_date - datetime(1970, 1, 1)).days)
                    attributes['shadowExpire'] = str(days_since_epoch)
            except ValueError:
                pass  # Use default (no expiry)
        
        if ldap_manager.add_entry(user_dn, object_classes, attributes):
            flash(f'User {username} created successfully.', 'success')
            return redirect(url_for('admin_users'))
        else:
            flash(f'Failed to create user. Error: {ldap_manager.last_error}', 'error')
    
    return render_template('admin/add_user.html')

@app.route('/admin/edit_entry/<path:entry_dn>')
@login_required
@admin_required
def admin_edit_entry(entry_dn):
    """Edit LDAP entry"""
    entries = ldap_manager.search_entries(entry_dn)
    entry_data = entries[0] if entries else {}
    
    return render_template('admin/edit_entry.html', entry_data=entry_data)

@app.route('/admin/update_entry', methods=['POST'])
@login_required
@admin_required
def admin_update_entry():
    """Update LDAP entry"""
    entry_dn = request.form['entry_dn']
    
    modifications = {}
    
    # Handle photo upload first
    if 'jpegPhoto' in request.files:
        photo_file = request.files['jpegPhoto']
        if photo_file and photo_file.filename:
            # Process photo upload
            photo_data = process_photo(photo_file)
            if photo_data:
                modifications['jpegPhoto'] = [(MODIFY_REPLACE, [photo_data])]
            else:
                flash('Failed to process photo. Please ensure it\'s a valid image file under 2MB.', 'error')
                return redirect(url_for('admin_edit_entry', entry_dn=entry_dn))
    
    # Process all other form fields
    for key, value in request.form.items():
        if key not in ['entry_dn', 'jpegPhoto'] and value.strip():
            if key == 'userPassword':
                # Hash password if it's being changed
                modifications[key] = [(MODIFY_REPLACE, [ldap_manager.create_ssha_password(value)])]
            else:
                modifications[key] = [(MODIFY_REPLACE, [value.strip()])]
    
    if modifications:
        if ldap_manager.modify_entry(entry_dn, modifications):
            flash('Entry updated successfully.', 'success')
        else:
            flash(f'Failed to update entry: {ldap_manager.last_error}', 'error')
    else:
        flash('No changes detected.', 'info')
    
    return redirect(url_for('admin_edit_entry', entry_dn=entry_dn))

@app.route('/admin/add_group', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_group():
    """Add new group"""
    if request.method == 'POST':
        group_name = request.form['group_name']
        description = request.form.get('description', '')
        initial_members = request.form.get('initial_members', '').strip()
        gid_number = request.form.get('gid_number', '').strip()
        enable_posix = request.form.get('enable_posix', '') == 'on'
        
        group_dn = f'cn={group_name},{LDAP_GROUPS_OU}'
        
        attributes = {
            'cn': group_name
        }
        
        if description.strip():
            attributes['description'] = description.strip()
        
        # Determine object classes based on POSIX enablement
        if enable_posix or gid_number:
            object_classes = ['posixGroup', 'top']
            # Add GID number for POSIX group
            if gid_number:
                try:
                    gid_num = int(gid_number)
                    if gid_num < 1000:
                        flash('GID number should be 1000 or higher for user groups.', 'warning')
                    attributes['gidNumber'] = str(gid_num)
                except ValueError:
                    flash('Invalid GID number. Using auto-generated GID.', 'warning')
                    attributes['gidNumber'] = str(ldap_manager.get_next_gid_number())
            else:
                attributes['gidNumber'] = str(ldap_manager.get_next_gid_number())
            
            # For POSIX groups, use memberUid instead of member
            if initial_members:
                # Parse member usernames (one per line or comma-separated)
                members = []
                for member in initial_members.replace(',', '\n').split('\n'):
                    member = member.strip()
                    if member:
                        # Extract username from DN if needed
                        if '=' in member and ',' in member:
                            # Extract uid from DN like uid=username,ou=People,dc=mylab,dc=lan
                            uid_part = member.split(',')[0]
                            if '=' in uid_part:
                                member = uid_part.split('=')[1]
                        members.append(member)
                
                if members:
                    attributes['memberUid'] = members
        else:
            object_classes = ['groupOfNames', 'top']
            
            # Add initial members if provided (for groupOfNames)
            if initial_members:
                # Parse member DNs (one per line or comma-separated)
                members = []
                for member in initial_members.replace(',', '\n').split('\n'):
                    member = member.strip()
                    if member:
                        # If it's just a username, convert to full DN
                        if '=' not in member:
                            member = f'uid={member},{LDAP_PEOPLE_OU}'
                        members.append(member)
                
                if members:
                    attributes['member'] = members
            else:
                # groupOfNames requires at least one member, use admin as placeholder
                attributes['member'] = [LDAP_ADMIN_DN]
        
        if ldap_manager.add_entry(group_dn, object_classes, attributes):
            posix_info = f" (POSIX Group, GID: {attributes.get('gidNumber', 'N/A')})" if enable_posix or gid_number else ""
            flash(f'Group {group_name} created successfully{posix_info}.', 'success')
            return redirect(url_for('admin_groups'))
        else:
            flash(f'Failed to create group. Error: {ldap_manager.last_error}', 'error')
    
    # Get available users for member selection
    users = ldap_manager.search_entries(LDAP_PEOPLE_OU, '(objectClass=person)')
    return render_template('admin/add_group.html', users=users)

@app.route('/admin/bulk_users', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_bulk_users():
    """Bulk user creation from CSV"""
    if request.method == 'POST':
        if 'csv_file' not in request.files:
            flash('No CSV file uploaded.', 'error')
            return redirect(request.url)
        
        file = request.files['csv_file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)
        
        if not file.filename.lower().endswith('.csv'):
            flash('Please upload a CSV file.', 'error')
            return redirect(request.url)
        
        return process_bulk_users_csv(file)
    
    return render_template('admin/bulk_users.html')

@app.route('/admin/download_sample_csv')
@login_required
@admin_required
def admin_download_sample_csv():
    """Download sample CSV file for bulk user creation"""
    import csv
    from io import StringIO
    
    # Create sample CSV data
    sample_data = [
        ['username', 'password', 'first_name', 'last_name', 'email', 'phone', 'department', 'title', 'posix_enabled', 'login_shell', 'home_directory'],
        ['john.doe', 'TempPass123!', 'John', 'Doe', 'john.doe@company.com', '555-1234', 'Engineering', 'Software Developer', 'yes', '/bin/bash', '/home/john.doe'],
        ['jane.smith', 'TempPass456!', 'Jane', 'Smith', 'jane.smith@company.com', '555-5678', 'Marketing', 'Marketing Manager', 'no', '', ''],
        ['bob.wilson', 'TempPass789!', 'Bob', 'Wilson', 'bob.wilson@company.com', '555-9012', 'HR', 'HR Specialist', 'yes', '/bin/zsh', '/home/bob.wilson']
    ]
    
    # Create CSV content
    output = StringIO()
    writer = csv.writer(output)
    writer.writerows(sample_data)
    
    # Create response
    response = app.response_class(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-disposition": "attachment; filename=bulk_users_sample.csv"}
    )
    
    return response

def process_bulk_users_csv(file):
    """Process uploaded CSV file and create users"""
    import csv
    from io import StringIO, TextIOWrapper
    
    try:
        # Read CSV content
        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)
        
        # Validate required columns
        required_columns = ['username', 'password', 'first_name', 'last_name', 'email']
        missing_columns = [col for col in required_columns if col not in csv_reader.fieldnames]
        
        if missing_columns:
            flash(f'Missing required columns: {", ".join(missing_columns)}', 'error')
            return redirect(url_for('admin_bulk_users'))
        
        results = {'success': 0, 'errors': []}
        
        for row_num, row in enumerate(csv_reader, start=2):  # Start from row 2 (after header)
            try:
                # Skip empty rows
                if not any(row.values()):
                    continue
                
                # Validate required fields
                missing_fields = [field for field in required_columns if not row.get(field, '').strip()]
                if missing_fields:
                    results['errors'].append(f'Row {row_num}: Missing required fields: {", ".join(missing_fields)}')
                    continue
                
                # Create user
                success = create_user_from_csv_row(row, row_num, results)
                if success:
                    results['success'] += 1
                    
            except Exception as e:
                results['errors'].append(f'Row {row_num}: Error processing row - {str(e)}')
        
        # Show results
        if results['success'] > 0:
            flash(f'Successfully created {results["success"]} users.', 'success')
        
        if results['errors']:
            error_msg = f'{len(results["errors"])} errors occurred:\n' + '\n'.join(results['errors'][:10])
            if len(results['errors']) > 10:
                error_msg += f'\n... and {len(results["errors"]) - 10} more errors.'
            flash(error_msg, 'error')
        
        return redirect(url_for('admin_users'))
        
    except Exception as e:
        flash(f'Error processing CSV file: {str(e)}', 'error')
        return redirect(url_for('admin_bulk_users'))

def create_user_from_csv_row(row, row_num, results):
    """Create a single user from CSV row data"""
    try:
        username = row['username'].strip()
        password = row['password'].strip()
        first_name = row['first_name'].strip()
        last_name = row['last_name'].strip()
        email = row['email'].strip()
        
        # Check if user already exists
        existing_user = ldap_manager.search_entries(LDAP_PEOPLE_OU, f'(uid={username})')
        if existing_user:
            results['errors'].append(f'Row {row_num}: User {username} already exists')
            return False
        
        # Validate email format
        import re
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            results['errors'].append(f'Row {row_num}: Invalid email format for {username}')
            return False
        
        # Build user attributes
        user_dn = f"uid={username},{LDAP_PEOPLE_OU}"
        
        # Base attributes
        attributes = {
            'uid': username,
            'cn': f"{first_name} {last_name}",
            'givenName': first_name,
            'sn': last_name,
            'mail': email,
            'userPassword': ldap_manager.create_ssha_password(password)
        }
        
        # Optional attributes
        if row.get('phone', '').strip():
            attributes['telephoneNumber'] = row['phone'].strip()
        if row.get('department', '').strip():
            attributes['departmentNumber'] = row['department'].strip()
        if row.get('title', '').strip():
            attributes['title'] = row['title'].strip()
        
        # Determine object classes and POSIX settings
        posix_enabled = row.get('posix_enabled', '').lower() in ['yes', 'true', '1', 'y']
        object_classes = ['inetOrgPerson', 'organizationalPerson', 'person', 'top']
        
        if posix_enabled:
            object_classes.extend(['posixAccount', 'shadowAccount'])
            
            # POSIX-specific attributes
            attributes['uidNumber'] = str(ldap_manager.get_next_uid_number())
            attributes['gidNumber'] = str(ldap_manager.get_next_gid_number())
            
            # Home directory
            home_dir = row.get('home_directory', '').strip()
            if not home_dir:
                home_dir = f'/home/{username}'
            attributes['homeDirectory'] = home_dir
            
            # Login shell
            login_shell = row.get('login_shell', '').strip()
            if not login_shell:
                login_shell = '/bin/bash'
            attributes['loginShell'] = login_shell
            
            # Shadow password attributes
            import time
            current_days = int(time.time() // 86400)
            attributes['shadowLastChange'] = str(current_days)
            attributes['shadowMax'] = '90'  # 90 days password expiry
            attributes['shadowWarning'] = '7'  # 7 days warning
            attributes['shadowMin'] = '0'
        
        # Create the user
        if ldap_manager.add_entry(user_dn, object_classes, attributes):
            return True
        else:
            results['errors'].append(f'Row {row_num}: Failed to create user {username} - {ldap_manager.last_error}')
            return False
            
    except Exception as e:
        results['errors'].append(f'Row {row_num}: Error creating user - {str(e)}')
        return False

@app.route('/admin/group_members/<path:group_dn>')
@login_required
@admin_required
def admin_group_members(group_dn):
    """Manage group members"""
    # Get group information
    groups = ldap_manager.search_entries(group_dn)
    group_data = groups[0] if groups else {}
    
    # Get all available users
    users = ldap_manager.search_entries(LDAP_PEOPLE_OU, '(objectClass=person)')
    
    # Get current members - handle both groupOfNames and posixGroup
    group_attributes = group_data.get('attributes', {})
    current_members = group_attributes.get('member', [])  # groupOfNames
    current_member_uids = group_attributes.get('memberUid', [])  # posixGroup
    
    # Get member details for groupOfNames (DN-based members)
    member_details = []
    for member_dn in current_members:
        try:
            member_info = ldap_manager.search_entries(member_dn)
            if member_info:
                member_details.append(member_info[0])
        except:
            # If member DN is invalid, add as raw DN
            member_details.append({
                'dn': member_dn,
                'attributes': {'cn': [member_dn.split(',')[0].split('=')[1]]}
            })
    
    # Get member details for posixGroup (username-based members)
    for member_uid in current_member_uids:
        try:
            # Search for user by uid
            user_dn = f'uid={member_uid},{LDAP_PEOPLE_OU}'
            member_info = ldap_manager.search_entries(user_dn)
            if member_info:
                member_details.append(member_info[0])
            else:
                # If user not found, add as placeholder
                member_details.append({
                    'dn': user_dn,
                    'attributes': {'cn': [member_uid], 'uid': [member_uid]}
                })
        except:
            # If lookup fails, add as placeholder
            member_details.append({
                'dn': f'uid={member_uid},{LDAP_PEOPLE_OU}',
                'attributes': {'cn': [member_uid], 'uid': [member_uid]}
            })
    
    return render_template('admin/group_members.html', 
                         group_data=group_data, 
                         users=users, 
                         member_details=member_details)

@app.route('/admin/add_group_member', methods=['POST'])
@login_required
@admin_required
def admin_add_group_member():
    """Add member to group"""
    group_dn = request.form['group_dn']
    member_dn = request.form['member_dn']
    
    # Get group information to determine type
    groups = ldap_manager.search_entries(group_dn)
    if not groups:
        flash('Group not found.', 'error')
        return redirect(url_for('admin_groups'))
    
    group_data = groups[0]
    group_attributes = group_data.get('attributes', {})
    object_classes = group_attributes.get('objectClass', [])
    
    # Determine if it's a POSIX group or groupOfNames
    is_posix_group = 'posixGroup' in object_classes
    
    if is_posix_group:
        # For POSIX groups, use memberUid with username
        username = member_dn
        if '=' in member_dn:
            # Extract username from DN
            username = member_dn.split(',')[0].split('=')[1]
        
        modifications = {
            'memberUid': [(MODIFY_ADD, [username])]
        }
    else:
        # For groupOfNames, use member with full DN
        if '=' not in member_dn:
            member_dn = f'uid={member_dn},{LDAP_PEOPLE_OU}'
        
        modifications = {
            'member': [(MODIFY_ADD, [member_dn])]
        }
    
    if ldap_manager.modify_entry(group_dn, modifications):
        flash('Member added to group successfully.', 'success')
    else:
        flash('Failed to add member to group.', 'error')
    
    return redirect(url_for('admin_group_members', group_dn=group_dn))

@app.route('/admin/remove_group_member', methods=['POST'])
@login_required
@admin_required
def admin_remove_group_member():
    """Remove member from group"""
    group_dn = request.form['group_dn']
    member_dn = request.form['member_dn']
    
    # Get group information to determine type
    groups = ldap_manager.search_entries(group_dn)
    if not groups:
        flash('Group not found.', 'error')
        return redirect(url_for('admin_groups'))
    
    group_data = groups[0]
    group_attributes = group_data.get('attributes', {})
    object_classes = group_attributes.get('objectClass', [])
    
    # Determine if it's a POSIX group or groupOfNames
    is_posix_group = 'posixGroup' in object_classes
    
    if is_posix_group:
        # For POSIX groups, use memberUid with username
        username = member_dn
        if '=' in member_dn:
            # Extract username from DN
            username = member_dn.split(',')[0].split('=')[1]
        
        modifications = {
            'memberUid': [(MODIFY_DELETE, [username])]
        }
    else:
        # For groupOfNames, use member with full DN
        modifications = {
            'member': [(MODIFY_DELETE, [member_dn])]
        }
    
    if ldap_manager.modify_entry(group_dn, modifications):
        flash('Member removed from group successfully.', 'success')
    else:
        flash('Failed to remove member from group.', 'error')
    
    return redirect(url_for('admin_group_members', group_dn=group_dn))

@app.route('/admin/delete_entry/<path:entry_dn>', methods=['POST'])
@login_required
@admin_required
def admin_delete_entry(entry_dn):
    """Delete LDAP entry"""
    if ldap_manager.delete_entry(entry_dn):
        flash('Entry deleted successfully.', 'success')
    else:
        flash('Failed to delete entry.', 'error')
    
    # Redirect based on entry type
    if 'ou=Groups' in entry_dn:
        return redirect(url_for('admin_groups'))
    elif 'ou=People' in entry_dn:
        return redirect(url_for('admin_users'))
    else:
        return redirect(url_for('admin_panel'))

@app.route('/admin/lock_user/<path:user_dn>', methods=['POST'])
@login_required
@admin_required
def admin_lock_user(user_dn):
    """Lock user account"""
    if ldap_manager.lock_user_account(user_dn):
        flash('User account locked successfully.', 'success')
    else:
        flash('Failed to lock user account.', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/unlock_user/<path:user_dn>', methods=['POST'])
@login_required
@admin_required
def admin_unlock_user(user_dn):
    """Unlock user account"""
    if ldap_manager.unlock_user_account(user_dn):
        flash('User account unlocked successfully.', 'success')
    else:
        flash('Failed to unlock user account.', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/set_password_expiry/<path:user_dn>', methods=['POST'])
@login_required
@admin_required
def admin_set_password_expiry(user_dn):
    """Set password expiry for POSIX user"""
    # First check if this is a POSIX user
    entries = ldap_manager.search_entries(user_dn)
    if not entries:
        flash('User not found.', 'error')
        return redirect(url_for('admin_edit_entry', entry_dn=user_dn))
    
    user_entry = entries[0]
    object_classes = user_entry.get('attributes', {}).get('objectClass', [])
    
    if 'posixAccount' not in object_classes:
        flash('Password expiry is only available for POSIX users.', 'warning')
        return redirect(url_for('admin_edit_entry', entry_dn=user_dn))
    
    days = request.form.get('expiry_days', '90')
    try:
        expiry_days = int(days)
        if ldap_manager.set_password_expiry(user_dn, expiry_days):
            flash(f'Password expiry set to {expiry_days} days from now.', 'success')
        else:
            flash('Failed to set password expiry.', 'error')
    except ValueError:
        flash('Invalid number of days.', 'error')
    
    return redirect(url_for('admin_edit_entry', entry_dn=user_dn))

@app.route('/admin/remove_photo/<path:user_dn>', methods=['POST'])
@login_required
@admin_required
def admin_remove_photo(user_dn):
    """Remove photo from user entry"""
    try:
        modifications = {
            'jpegPhoto': [(MODIFY_DELETE, [])]
        }
        
        if ldap_manager.modify_entry(user_dn, modifications):
            flash('Photo removed successfully.', 'success')
        else:
            flash(f'Failed to remove photo: {ldap_manager.last_error}', 'error')
    except Exception as e:
        flash(f'Error removing photo: {str(e)}', 'error')
    
    return redirect(url_for('admin_edit_entry', entry_dn=user_dn))

if __name__ == '__main__':
    # Production configuration - debug disabled for security
    app.run(debug=False, host='0.0.0.0', port=5000)
