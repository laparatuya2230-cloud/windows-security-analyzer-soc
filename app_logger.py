import logging

def setup_logger():
    logger = logging.getLogger("security_analyzer")

    if logger.hasHandlers():
        return logger

    logger.setLevel(logging.INFO)

    # consola
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # archivo
    file_handler = logging.FileHandler("audit.log")
    file_handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s - %(message)s",
        "%Y-%m-%d %H:%M:%S"
    )

    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger