import logging
import os, os.path
from datetime import datetime

def getLogger(logDir=None):

  if logDir==None:
    logDir="/tmp/roro/"

  if not os.path.exists(logDir):
    os.makedirs(logDir)

  fileName = datetime.now().strftime("%Y_%m_%d_%H_%M_")
  logging.basicConfig(filename=logDir+"/" + fileName +"assessment.log", level=logging.ERROR)


  logger = logging.getLogger()

  formatter = logging.Formatter('[%(levelname)s|%(filename)s:%(lineno)s]%(asctime)s > %(message)s')

  fileHandler = logging.FileHandler("./test.log")
  streamHandler = logging.StreamHandler()

  fileHandler.setFormatter(formatter)
  streamHandler.setFormatter(formatter)

  logger.addHandler(fileHandler)
  logger.addHandler(streamHandler)

  return logger