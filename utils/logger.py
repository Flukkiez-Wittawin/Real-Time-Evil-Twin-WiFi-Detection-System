import logging
import os

def setup_logger():
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    logger = logging.getLogger('WiFiDetector')
    logger.setLevel(logging.INFO)
    
    # File handler
    fh = logging.FileHandler('logs/app.log')
    fh.setLevel(logging.INFO)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    return logger

logger = setup_logger()
