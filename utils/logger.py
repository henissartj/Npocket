import logging

def setup_logger(name="npocket", level=logging.INFO):
    """
    Configure and return the main logger for Npocket.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate logs if the logger is already configured
    if not logger.handlers:
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(module)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        logger.addHandler(console_handler)
        
    return logger

logger = setup_logger()
