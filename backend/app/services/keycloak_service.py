import os
import logging
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakError

logger = logging.getLogger("zero_trust_backend.keycloak")

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak.platform-identity.svc.cluster.local/")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "ZeroTrust-Realm")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "jit-backend-api")
KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET", "")

_admin = None

def _get_admin() -> KeycloakAdmin:
    global _admin
    if not _admin:
        _admin = KeycloakAdmin(
            server_url=KEYCLOAK_URL,
            client_id=KEYCLOAK_CLIENT_ID,
            realm_name=KEYCLOAK_REALM,
            client_secret_key=KEYCLOAK_CLIENT_SECRET,
            verify=False,
        )
    return _admin

def _ensure_group_exists(admin: KeycloakAdmin, group_name: str) -> str:
    """Returns the group ID, creating the group if it doesn't exist."""
    groups = admin.get_groups()
    for g in groups:
        if g.get("name") == group_name:
            return g.get("id")
    # Create the group
    admin.create_group({"name": group_name})
    
    # Reload to get ID
    groups = admin.get_groups()
    for g in groups:
        if g.get("name") == group_name:
            return g.get("id")
    raise ValueError(f"Could not find or create group {group_name}")

def grant_jit_access(email: str, app_name: str) -> bool:
    try:
        admin = _get_admin()
        
        # 1. Obținem UUID-ul utilizatorului pe baza email-ului
        # FreeIPA users synced usually have their email as username or email field
        users = admin.get_users({"email": email})
        if not users:
            # Maybe fallback to username search if email is used as username
            users = admin.get_users({"username": email.split("@")[0]})
        
        if not users:
            logger.error(f"User with email/username {email} not found in Keycloak.")
            return False
        
        user_id = users[0]["id"]
        group_name = f"jit-access-{app_name}"
        
        # 2. Obținem UUID-ul grupului pentru aplicația target (creăm dacă nu există)
        group_id = _ensure_group_exists(admin, group_name)
        
        # 3. Adăugăm utilizatorul în grup
        admin.group_user_add(user_id=user_id, group_id=group_id)
        logger.info(f"Granted JIT access: added user {email} to group {group_name}")
        return True
    except KeycloakError as e:
        logger.error(f"Keycloak error granting access: {e}")
        return False
    except Exception as e:
        logger.error(f"System error granting access: {e}")
        return False

def revoke_jit_access(email: str, app_name: str) -> bool:
    try:
        admin = _get_admin()
        
        users = admin.get_users({"email": email})
        if not users:
            users = admin.get_users({"username": email.split("@")[0]})
            
        if not users:
            return True # Trivial success if user does not exist
        
        user_id = users[0]["id"]
        group_name = f"jit-access-{app_name}"
        
        groups = admin.get_groups({"search": group_name})
        group_id = None
        for g in groups:
            if g.get("name") == group_name:
                group_id = g.get("id")
                break
                
        if not group_id:
            return True # Group doesn't exist, already revoked
            
        admin.group_user_remove(user_id=user_id, group_id=group_id)
        logger.info(f"Revoked JIT access: removed user {email} from group {group_name}")
        return True
    except KeycloakError as e:
        logger.error(f"Keycloak error revoking access: {e}")
        return False
    except Exception as e:
        logger.error(f"System error revoking access: {e}")
        return False
