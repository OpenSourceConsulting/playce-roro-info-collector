import logging

logging.basicConfig(filename="./test.log", level=logging.DEBUG)

logger = logging.getLogger()

formatter = logging.Formatter('[%(levelname)s|%(filename)s:%(lineno)s][%(asctime)s] %(message)s')

fileHandler = logging.FileHandler("./test.log")
streamHandler = logging.StreamHandler()

fileHandler.setFormatter(formatter)
streamHandler.setFormatter(formatter)

logger.addHandler(fileHandler)
logger.addHandler(streamHandler)

logger.debug("debug")
