from ui import run_app
import logging


# =========================
# 🔧 LOGGER GLOBAL
# =========================
def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    return logging.getLogger("scanner")


# =========================
# 🚀 ENTRY POINT
# =========================
if __name__ == "__main__":
    logger = setup_logger()
    logger.info("Iniciando Windows Vuln Scanner...")

    run_app()