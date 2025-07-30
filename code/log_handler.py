import logging
import sys

# Define the log file path
log_file = "/var/log/virusCleaner.log"

# Configure logging with basic format
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger()
logger.setLevel(logging.INFO)

try:
    log_handler = logging.FileHandler(log_file)
    log_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)
except PermissionError:
    print("Error: Permission denied. Please run the script with sudo.", file=sys.stderr)
    sys.exit(1)  # Exit the script to enforce sudo usage


def log_info(message: str) -> None:
    """Log general information to both the console and log file."""
    logger.info(message)

def log_error(message: str) -> None:
    """Log error message to both the console and log file."""
    logger.error(message)

def log_warning(message: str) -> None:
    """Log warning message to both the console and log file."""
    logger.warning(message)