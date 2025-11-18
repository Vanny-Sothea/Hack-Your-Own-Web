from ..core.celery_app import celery_app
import time

@celery_app.task
def scan_website_task(url: str):
    print(f"Scanning URL: {url}")
    print(f"Simulating scan for 4 seconds...")
    time.sleep()  # Simulate a time-consuming scan
    print(f"Completed scanning URL: {url}")
    