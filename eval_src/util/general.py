from pathlib import Path
import logging
from datetime import datetime

def ensure_dir_exists(fp, fp_type="dir"):
    p = Path(fp)
    if fp_type=="dir" and not p.is_dir():
        p.mkdir(parents=True, exist_ok=True)
    elif fp_type == "file" and not p.is_file():
        p.parent.mkdir(parents=True, exist_ok=True)

# src: https://stackoverflow.com/questions/11232230/logging-to-two-files-with-different-settings
def setup_logger(name, log_file, root_log_file=None, level=logging.DEBUG):
    """To setup as many loggers as you want"""
    
    formatter = logging.Formatter('%(asctime)s - [%(levelname)s]: %(message)s')

    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    handler = logging.FileHandler(log_file, 'w+')
    handler.setFormatter(formatter)
    handler.setLevel(level)
    logger.addHandler(handler)

    if root_log_file:
        root_handler = logging.FileHandler(root_log_file, 'w+')
        root_handler.setLevel(logging.INFO)
        root_handler.setFormatter(formatter)
        logger.addHandler(root_handler)

    return logger

def log(msg, level=logging.INFO, logger=None):
    if logger:
        if level == logging.DEBUG:
            logger.debug(msg)
        elif level == logging.INFO:
            logger.info(msg)
        elif level == logging.WARNING:
            logger.warning(msg)
        elif level == logging.ERROR:
            logger.error(msg)
        elif level == logging.CRITICAL:
            logger.critical(msg)
        else:
            logger.info(msg)
    else:
        print(msg)

def print_log(msg):
    print(f"[{datetime.now()}] {msg}")

def format_filename(fn):
    if ":" in fn:
        fn = fn.replace(":", "_")
    return fn