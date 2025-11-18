from celery import Celery
from celery.schedules import crontab
from .config import Config

celery_app = Celery(
    "backend_tasks",
    broker=Config.CELERY_BROKER_URL,
    backend=Config.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.domain_verification", 
        "app.tasks.scan",
        "app.tasks.domain_verification_scheduled"
    ]
)

celery_app.conf.update(
    task_track_started=True,
    task_time_limit=30 * 60, #30 min max runtime
    task_soft_time_limit=25 * 60, #25 min warning
    broker_connection_retry_on_startup=True, #retry if broker is not available at startup
    result_expires=3600, #1 hour expiration for results
    task_acks_late=True, # Acknowledge tasks after they have been processed
    worker_prefetch_multiplier=1, # Disable prefetching to ensure fair task distribution
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone="Asia/Phnom_Penh",
    enable_utc=True,
)

# Route tasks to dedicated queues
celery_app.conf.task_routes = {
    'app.tasks.domain_verification.*': {'queue': 'domain_verification_queue'},
    'app.tasks.scan.*': {'queue': 'scan_queue'},
}

# Scheduled (beat) tasks
celery_app.conf.beat_schedule = {
    "daily-domain-maintenance": {
        "task": "app.tasks.domain_verification_scheduled.scheduled_domain_maintenance",
        "schedule": crontab(hour=0, minute=0),  # every day at midnight
        # "schedule": 60,  # for testing, running every 60 seconds
        "options": {"queue": "domain_verification_queue"},
    }
}