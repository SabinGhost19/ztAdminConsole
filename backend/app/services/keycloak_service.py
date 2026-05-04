import os
import logging
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakError
from app.middleware.errors import ZeroTrustException

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

# --- Phase 4b: Group Management Functions ---

def list_all_groups() -> list[dict]:
    """List all groups in the realm"""
    try:
        admin = _get_admin()
        groups = admin.get_groups()
        return groups
    except KeycloakError as e:
        logger.error(f"Keycloak error listing groups: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_LIST_GROUPS_FAILED",
            message="Nu pot lista grupurile din Keycloak.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica client credentials si rolurile pentru service account.",
        )
    except Exception as e:
        logger.error(f"System error listing groups: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_LIST_GROUPS_FAILED",
            message="Eroare interna la listarea grupurilor.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica conectivitatea la Keycloak.",
        )

def create_group_keycloak(name: str, description: str = "") -> str:
    """Create a new group, return its ID"""
    try:
        admin = _get_admin()
        group_data = {"name": name}
        if description:
            group_data["attributes"] = {"description": [description]}
        
        admin.create_group(group_data)
        
        # Reload to get ID
        groups = admin.get_groups()
        for g in groups:
            if g.get("name") == name:
                logger.info(f"Created group {name} with ID {g.get('id')}")
                return g.get("id")
        
        raise ValueError(f"Could not find created group {name}")
    except KeycloakError as e:
        logger.error(f"Keycloak error creating group: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_CREATE_GROUP_FAILED",
            message="Nu pot crea grupul in Keycloak.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica permisiunile service account.",
        )
    except Exception as e:
        logger.error(f"System error creating group: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_CREATE_GROUP_FAILED",
            message="Eroare interna la crearea grupului.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica conectivitatea la Keycloak.",
        )


def update_group_keycloak(group_id: str, name: str | None = None, description: str | None = None) -> bool:
    """Update a group's name and/or description"""
    try:
        admin = _get_admin()
        group = admin.get_group(group_id)
        if not group:
            return False

        updated_name = (name or "").strip() if name is not None else group.get("name", "")
        payload: dict = {"name": updated_name}

        current_attrs = group.get("attributes", {}) or {}
        if description is not None:
            desc_value = description.strip()
            if desc_value:
                current_attrs["description"] = [desc_value]
            else:
                current_attrs.pop("description", None)
        if current_attrs:
            payload["attributes"] = current_attrs

        admin.update_group(group_id, payload)
        logger.info(f"Updated group {group_id}")
        return True
    except KeycloakError as e:
        logger.error(f"Keycloak error updating group: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_UPDATE_GROUP_FAILED",
            message="Nu pot actualiza grupul in Keycloak.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica permisiunile service account.",
        )
    except Exception as e:
        logger.error(f"System error updating group: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_UPDATE_GROUP_FAILED",
            message="Eroare interna la actualizarea grupului.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica conectivitatea la Keycloak.",
        )


def delete_group_keycloak(group_id: str) -> bool:
    """Delete a group by ID"""
    try:
        admin = _get_admin()
        admin.delete_group(group_id)
        logger.info(f"Deleted group {group_id}")
        return True
    except KeycloakError as e:
        logger.error(f"Keycloak error deleting group: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_DELETE_GROUP_FAILED",
            message="Nu pot sterge grupul din Keycloak.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica permisiunile service account.",
        )
    except Exception as e:
        logger.error(f"System error deleting group: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_DELETE_GROUP_FAILED",
            message="Eroare interna la stergerea grupului.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica conectivitatea la Keycloak.",
        )

def get_user_groups(user_id: str) -> list[dict]:
    """Get all groups a user belongs to"""
    try:
        admin = _get_admin()
        groups = admin.get_user_groups(user_id)
        return groups
    except KeycloakError as e:
        logger.error(f"Keycloak error getting user groups for {user_id}: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_USER_GROUPS_FAILED",
            message="Nu pot prelua grupurile utilizatorului.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica permisiunile service account.",
        )
    except Exception as e:
        logger.error(f"System error getting user groups for {user_id}: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_USER_GROUPS_FAILED",
            message="Eroare interna la preluarea grupurilor utilizatorului.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica conectivitatea la Keycloak.",
        )

def add_user_to_group_keycloak(user_id: str, group_id: str) -> bool:
    """Add a user to a group"""
    try:
        admin = _get_admin()
        admin.group_user_add(user_id=user_id, group_id=group_id)
        logger.info(f"Added user {user_id} to group {group_id}")
        return True
    except KeycloakError as e:
        logger.error(f"Keycloak error adding user to group: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_ADD_USER_GROUP_FAILED",
            message="Nu pot adauga userul in grup.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica permisiunile service account.",
        )
    except Exception as e:
        logger.error(f"System error adding user to group: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_ADD_USER_GROUP_FAILED",
            message="Eroare interna la adaugarea userului in grup.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica conectivitatea la Keycloak.",
        )

def remove_user_from_group_keycloak(user_id: str, group_id: str) -> bool:
    """Remove a user from a group"""
    try:
        admin = _get_admin()
        admin.group_user_remove(user_id=user_id, group_id=group_id)
        logger.info(f"Removed user {user_id} from group {group_id}")
        return True
    except KeycloakError as e:
        logger.error(f"Keycloak error removing user from group: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_REMOVE_USER_GROUP_FAILED",
            message="Nu pot elimina userul din grup.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica permisiunile service account.",
        )
    except Exception as e:
        logger.error(f"System error removing user from group: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_REMOVE_USER_GROUP_FAILED",
            message="Eroare interna la eliminarea userului din grup.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica conectivitatea la Keycloak.",
        )


def update_user_status_keycloak(user_id: str, enabled: bool) -> bool:
    """Enable or disable a user account in Keycloak"""
    try:
        admin = _get_admin()
        admin.update_user(user_id=user_id, payload={"enabled": enabled})
        logger.info(f"Updated user {user_id} enabled={enabled}")
        return True
    except KeycloakError as e:
        logger.error(f"Keycloak error updating user status: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_UPDATE_USER_STATUS_FAILED",
            message="Nu pot actualiza statusul utilizatorului.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica permisiunile service account.",
        )
    except Exception as e:
        logger.error(f"System error updating user status: {e}")
        raise ZeroTrustException(
            error_code="KEYCLOAK_UPDATE_USER_STATUS_FAILED",
            message="Eroare interna la actualizarea statusului utilizatorului.",
            technical_details=str(e),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica conectivitatea la Keycloak.",
        )

