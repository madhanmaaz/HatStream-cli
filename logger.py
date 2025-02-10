import logging

class PrintLogger(logging.StreamHandler):
    def emit(self, record):
        log_entry = self.format(record)
        print(log_entry)

# Configure logging to use print instead of sys.stdout
logger = logging.getLogger()
logger.handlers.clear()  # Remove default handlers
handler = PrintLogger()
formatter = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", "%H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
