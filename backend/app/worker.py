
from app.core.celery_app import celery_app

# Import tasks to ensure they're registered
from app.tasks import scan_tasks, domain_verification  # noqa: F401

# Export celery instance for Celery CLI discovery
celery = celery_app

if __name__ == "__main__":
    celery_app.start()
