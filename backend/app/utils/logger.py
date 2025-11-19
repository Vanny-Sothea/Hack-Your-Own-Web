import logging
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Any, Dict

class StructuredFormatter(logging.Formatter):
    """
    Structured JSON formatter for better log parsing and analysis.
    Outputs logs in JSON format with context fields.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        if hasattr(record, "scan_id"):
            log_data["scan_id"] = record.scan_id
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id
        if hasattr(record, "target_url"):
            log_data["target_url"] = record.target_url
        if hasattr(record, "duration"):
            log_data["duration_ms"] = record.duration

        return json.dumps(log_data)


class HumanReadableFormatter(logging.Formatter):
    """Human-readable formatter for console output"""
    def __init__(self):
        super().__init__(
            fmt="%(asctime)s - %(levelname)-8s - [%(name)s:%(funcName)s:%(lineno)d] - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )


# Create formatters
structured_formatter = StructuredFormatter()
human_formatter = HumanReadableFormatter()

# Create console handler (human-readable for development)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(human_formatter)
stream_handler.setLevel(logging.INFO)

# Try to add file handlers (structured JSON for production)
handlers = [stream_handler]

# Ensure logs directory exists
log_dir = Path("logs")
try:
    log_dir.mkdir(exist_ok=True, parents=True)

    # Main application log (JSON format)
    app_log_handler = logging.FileHandler(log_dir / "app.log")
    app_log_handler.setFormatter(structured_formatter)
    app_log_handler.setLevel(logging.INFO)
    handlers.append(app_log_handler)

    # Error log (JSON format, errors only)
    error_log_handler = logging.FileHandler(log_dir / "error.log")
    error_log_handler.setFormatter(structured_formatter)
    error_log_handler.setLevel(logging.ERROR)
    handlers.append(error_log_handler)

    # Scan-specific log (JSON format)
    scan_log_handler = logging.FileHandler(log_dir / "scan.log")
    scan_log_handler.setFormatter(structured_formatter)
    scan_log_handler.setLevel(logging.DEBUG)
    # Will be used by scan-related loggers
    handlers.append(scan_log_handler)

except (PermissionError, OSError) as e:
    # Log to stdout only if file logging fails
    print(f"Warning: Cannot write to log file ({e}), logging to stdout only", file=sys.stderr)

# Initialize logger
logger = logging.getLogger()
logger.handlers = handlers
logger.setLevel(logging.DEBUG)  # Capture all levels, handlers will filter

# Create specialized loggers
scan_logger = logging.getLogger("scan")
scan_logger.setLevel(logging.DEBUG)

metrics_logger = logging.getLogger("metrics")
metrics_logger.setLevel(logging.INFO)

# Silence noisy loggers
logging.getLogger("watchfiles").propagate = False
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("docker").setLevel(logging.WARNING)