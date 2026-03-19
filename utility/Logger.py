from logging.redisLogger import RedisLogger
from config.settings import settings

redis_logger = RedisLogger(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT
    )
redis_logger.connect()
Logger = redis_logger.log