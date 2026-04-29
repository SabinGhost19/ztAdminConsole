"""
Background Tasks for JIT State Management
Includes periodic cleanup and monitoring jobs
"""

import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger("zero_trust_backend.background_tasks")

_scheduler: BackgroundScheduler | None = None


def init_background_scheduler():
    """Initialize and start the background scheduler"""
    global _scheduler
    
    if _scheduler is not None:
        return
    
    try:
        _scheduler = BackgroundScheduler()
        
        # Job 1: Clean up old JIT sessions daily at 2 AM
        from app.services.jit_state_service import cleanup_expired_sessions
        _scheduler.add_job(
            cleanup_expired_sessions,
            CronTrigger(hour=2, minute=0),
            id="cleanup_expired_sessions",
            name="Clean up expired JIT sessions",
            replace_existing=True,
        )
        
        # Job 2: Log JIT session statistics every hour
        from app.services.jit_state_service import get_session_stats
        _scheduler.add_job(
            _log_session_stats,
            CronTrigger(minute=0),
            id="log_session_stats",
            name="Log JIT session statistics",
            replace_existing=True,
        )
        
        _scheduler.start()
        logger.info("Background scheduler started successfully")
    except Exception as e:
        logger.error(f"Failed to start background scheduler: {e}")


def shutdown_background_scheduler():
    """Shutdown the background scheduler"""
    global _scheduler
    
    if _scheduler is None:
        return
    
    try:
        _scheduler.shutdown()
        _scheduler = None
        logger.info("Background scheduler shut down successfully")
    except Exception as e:
        logger.error(f"Error shutting down background scheduler: {e}")


def _log_session_stats():
    """Internal job: Log current session statistics"""
    try:
        from app.services.jit_state_service import get_session_stats
        stats = get_session_stats()
        logger.info(f"JIT Session Stats: {stats}")
    except Exception as e:
        logger.error(f"Error logging session stats: {e}")
