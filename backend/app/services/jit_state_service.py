"""
JIT State Machine Service
Manages the lifecycle of JIT (Just-In-Time) access sessions:
PENDING → ACTIVE → EXPIRED/REVOKED
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional

from app.core.state_db import write_state, read_state, delete_state, list_state_by_type

logger = logging.getLogger("zero_trust_backend.jit_state")

# State constants
STATE_PENDING = "PENDING"
STATE_ACTIVE = "ACTIVE"
STATE_EXPIRED = "EXPIRED"
STATE_REVOKED = "REVOKED"


def create_jit_session_entry(
    user_email: str,
    app_name: str,
    duration_minutes: int,
    requested_by: str = None
) -> Dict[str, Any]:
    """
    Create a new JIT session entry in PENDING state.
    Returns the session data with session_id.
    """
    session_id = f"jit-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=duration_minutes)
    
    session_data = {
        "session_id": session_id,
        "user_email": user_email,
        "app_name": app_name,
        "state": STATE_PENDING,
        "requested_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "approved_by": None,
        "approved_at": None,
        "revoked_by": None,
        "revoked_at": None,
        "reason": None,
    }
    
    # Store in state DB
    cache_key = f"jit_session:{session_id}"
    write_state(
        cache_key=cache_key,
        payload=session_data,
        state_type="jit_session",
        namespace="default",
        resource_name=session_id,
    )
    
    logger.info(f"Created JIT session {session_id} for {user_email}:{app_name}")
    return session_data


def approve_session(session_id: str, approver_email: str) -> bool:
    """
    Move a session from PENDING to ACTIVE state.
    Only PENDING sessions can be approved.
    """
    try:
        cache_key = f"jit_session:{session_id}"
        session_data = read_state(cache_key)
        
        if not session_data:
            logger.warning(f"Session {session_id} not found")
            return False
        
        if session_data.get("state") != STATE_PENDING:
            logger.warning(f"Cannot approve session {session_id} in state {session_data.get('state')}")
            return False
        
        now = datetime.now(timezone.utc)
        session_data["state"] = STATE_ACTIVE
        session_data["approved_by"] = approver_email
        session_data["approved_at"] = now.isoformat()
        
        write_state(
            cache_key=cache_key,
            payload=session_data,
            state_type="jit_session",
            namespace="default",
            resource_name=session_id,
        )
        
        logger.info(f"Session {session_id} approved by {approver_email}")
        
        # Grant actual Keycloak access
        from app.services.keycloak_service import grant_jit_access
        grant_jit_access(session_data["user_email"], session_data["app_name"])
        
        return True
    except Exception as e:
        logger.error(f"Error approving session {session_id}: {e}")
        return False


def revoke_session_explicit(session_id: str, revoker_email: str, reason: str = None) -> bool:
    """
    Revoke an active or pending session.
    Move to REVOKED state.
    """
    try:
        cache_key = f"jit_session:{session_id}"
        session_data = read_state(cache_key)
        
        if not session_data:
            logger.warning(f"Session {session_id} not found")
            return False
        
        current_state = session_data.get("state")
        if current_state not in [STATE_PENDING, STATE_ACTIVE]:
            logger.warning(f"Cannot revoke session {session_id} in state {current_state}")
            return False
        
        now = datetime.now(timezone.utc)
        session_data["state"] = STATE_REVOKED
        session_data["revoked_by"] = revoker_email
        session_data["revoked_at"] = now.isoformat()
        session_data["reason"] = reason or "Manual revocation"
        
        write_state(
            cache_key=cache_key,
            payload=session_data,
            state_type="jit_session",
            namespace="default",
            resource_name=session_id,
        )
        
        # Revoke Keycloak access if it was active
        if current_state == STATE_ACTIVE:
            from app.services.keycloak_service import revoke_jit_access
            revoke_jit_access(session_data["user_email"], session_data["app_name"])
        
        logger.info(f"Session {session_id} revoked by {revoker_email}. Reason: {reason}")
        return True
    except Exception as e:
        logger.error(f"Error revoking session {session_id}: {e}")
        return False


def expire_session(session_id: str, reason: str = "Auto-expired") -> bool:
    """
    Mark a session as EXPIRED. Called by background job.
    """
    try:
        cache_key = f"jit_session:{session_id}"
        session_data = read_state(cache_key)
        
        if not session_data:
            return False
        
        if session_data.get("state") not in [STATE_PENDING, STATE_ACTIVE]:
            return False  # Already in terminal state
        
        now = datetime.now(timezone.utc)
        session_data["state"] = STATE_EXPIRED
        session_data["revoked_at"] = now.isoformat()
        session_data["reason"] = reason
        
        write_state(
            cache_key=cache_key,
            payload=session_data,
            state_type="jit_session",
            namespace="default",
            resource_name=session_id,
        )
        
        # Revoke Keycloak access if it was active
        if session_data.get("state") == STATE_ACTIVE:
            from app.services.keycloak_service import revoke_jit_access
            revoke_jit_access(session_data["user_email"], session_data["app_name"])
        
        logger.info(f"Session {session_id} expired: {reason}")
        return True
    except Exception as e:
        logger.error(f"Error expiring session {session_id}: {e}")
        return False


def get_active_sessions() -> List[Dict[str, Any]]:
    """
    Get all sessions in ACTIVE or PENDING state.
    Check for expired sessions and auto-expire them.
    """
    try:
        all_sessions = list_state_by_type("jit_session")
        now = datetime.now(timezone.utc)
        
        active_and_pending = []
        for session in all_sessions:
            state = session.get("state")
            
            # Skip already terminal states
            if state in [STATE_EXPIRED, STATE_REVOKED]:
                continue
            
            # Check if expired
            expires_at_str = session.get("expires_at")
            if expires_at_str:
                expires_at = datetime.fromisoformat(expires_at_str)
                if now > expires_at:
                    # Auto-expire this session
                    session_id = session.get("session_id")
                    expire_session(session_id, "Auto-expired: TTL reached")
                    continue
            
            active_and_pending.append(session)
        
        return active_and_pending
    except Exception as e:
        logger.error(f"Error getting active sessions: {e}")
        return []


def cleanup_expired_sessions(days_to_keep: int = 7) -> int:
    """
    Background task: Delete old EXPIRED/REVOKED sessions from state DB.
    Returns number of sessions deleted.
    """
    try:
        all_sessions = list_state_by_type("jit_session")
        now = datetime.now(timezone.utc)
        cutoff_date = now - timedelta(days=days_to_keep)
        
        deleted_count = 0
        for session in all_sessions:
            state = session.get("state")
            if state not in [STATE_EXPIRED, STATE_REVOKED]:
                continue
            
            # Check when it was revoked/expired
            timestamp_str = session.get("revoked_at") or session.get("approved_at")
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str)
                if timestamp < cutoff_date:
                    session_id = session.get("session_id")
                    cache_key = f"jit_session:{session_id}"
                    delete_state(cache_key)
                    deleted_count += 1
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old JIT sessions")
        
        return deleted_count
    except Exception as e:
        logger.error(f"Error cleaning up expired sessions: {e}")
        return 0


def get_session_stats() -> Dict[str, Any]:
    """
    Get statistics on JIT sessions.
    """
    try:
        all_sessions = list_state_by_type("jit_session")
        
        stats = {
            "total_sessions": len(all_sessions),
            "pending": 0,
            "active": 0,
            "expired": 0,
            "revoked": 0,
            "by_app": {},
        }
        
        for session in all_sessions:
            state = session.get("state")
            stats[state.lower()] = stats.get(state.lower(), 0) + 1
            
            app_name = session.get("app_name")
            if app_name not in stats["by_app"]:
                stats["by_app"][app_name] = {"pending": 0, "active": 0, "expired": 0, "revoked": 0}
            stats["by_app"][app_name][state.lower()] += 1
        
        return stats
    except Exception as e:
        logger.error(f"Error getting session stats: {e}")
        return {}
