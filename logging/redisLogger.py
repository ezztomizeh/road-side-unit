from datetime import datetime
from logging.Logger import Logger
import redis

class RedisLogger(Logger):

    __instance = None
    __connection = None

    def __new__(cls, *args, **kwargs):
        if cls.__instance is None:
            cls.__instance = super(RedisLogger, cls).__new__(cls)
        return cls.__instance
    
    def __init__(self, host: str, port: int):
        self.setHost(host)
        self.setPort(port)

    def setHost(self, host: str) -> None:
        self.__host = host

    def setPort(self, port: int) -> None:
        self.__port = port

    def getHost(self) -> str:
        return self.__host
    
    def getPort(self) -> int:
        return self.__port
    
    def connect(self) -> None:
        if self.__connection is None:
            self.__connection = redis.Redis(host=self.getHost(), port=self.getPort())

    def disconnect(self) -> None:
        if self.__connection is not None:
            self.__connection.close()
            self.__connection = None
    
    def log(self, message: str, client_id: str) -> None:
        if self.__connection is None:
            self.connect()
            
        timestamp = datetime.now().isoformat()
        log_entry = f"{message}"
        self.__connection.set(f"log:{timestamp}:{client_id}", log_entry)