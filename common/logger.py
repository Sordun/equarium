from loguru import logger
from datetime import datetime

log_file = f'{datetime.now().date()}.log'
logger.add(log_file,
           rotation="1 day",  # Создавать новый файл каждый день
           encoding='utf-8',
           format="{time:YYYY-MM-DD в HH:mm:ss} | {file}:{line} | {level} | {message}")
logger.info("Приложение запущено.")
