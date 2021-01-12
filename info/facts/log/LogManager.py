import logging
import os
import subprocess


class LogManager(object):
    logger = None

    @classmethod
    def set_logging(cls, log_dir):
        '''
                create and set logger object

                :param log_dir:
                :return:
                '''
        if not log_dir:
            log_dir = './assessments/logs'

        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                            datefmt='%m-%d %H:%M',
                            filename=os.path.join(log_dir,
                                                  os.path.splitext(os.path.basename(__file__))[0] + 'assessment.log'),
                            filemode='a')

        logging.getLogger("paramiko").setLevel(logging.WARNING)
        cls.logger = logging.getLogger(__name__)


    @classmethod
    def logging(cls, function):

        def inner(*args, **kwargs):
            result = function(*args, **kwargs)
            cls.logger.debug("Finished {} with err :{}".format(function.__name__, result))
            return result

        return inner

    @classmethod
    def run_subprocess(cls, cmd1, log_enabled=True):
        '''
        Execute linux system command and logging results

        :param cmd1:
        :param log_enabled:
        :return:
        '''

        try:
            proc = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (out, err) = proc.communicate()

            if out and log_enabled:
                cls.logger.info(out)

            if err:
                cls.logger.error(err)

            return out, err

        except Exception as e:
            cls.logger.error("Error : RUN (%s)" % str(e))

    # @staticmethod
    # def run_subprocess(cmd1, log_enabled=True):
    #     '''
    #     Execute linux system command and logging results
    #
    #     :param cmd1:
    #     :param log_enabled:
    #     :return:
    #     '''
    #
    #     try:
    #         proc = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #         (out, err) = proc.communicate()
    #
    #         if out and log_enabled:
    #             LogManager.logger.info(out)
    #
    #         if err:
    #             LogManager.logger.error(err)
    #
    #         return out, err
    #
    #     except Exception as e:
    #         LogManager.logger.error("Error : RUN (%s)" % str(e))
