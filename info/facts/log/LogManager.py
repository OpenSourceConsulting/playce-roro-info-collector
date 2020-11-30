import logging
import logging.config
import json
import os, os.path
from datetime import datetime


def getLogger(logDir=None):
    if logDir is None:
        logDir = "/tmp/roro/"

    if not os.path.exists(logDir):
        os.makedirs(logDir)

    fileName = logDir + "/" + datetime.now().strftime("%Y_%m_%d_%H_%M_") + "assessment.log"
    logging.basicConfig(filename=fileName, level=logging.DEBUG)

    logger = logging.getLogger(__name__)

    formatter = logging.Formatter('[%(levelname)s|%(filename)s:%(lineno)s] > %(message)s')

    fileHandler = logging.FileHandler(fileName)
    streamHandler = logging.StreamHandler()

    fileHandler.setFormatter(formatter)
    streamHandler.setFormatter(formatter)

    logger.addHandler(fileHandler)
    logger.addHandler(streamHandler)

    return logger
