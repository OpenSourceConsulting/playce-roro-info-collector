from functools import wraps
import logging


def arglist( *args, **kwargs ):
    s = ""
    for a in args:
        s += repr(a) + ","
    for k,v in kwargs.items():
        s += "{k}={v}, ".format( k= k, v=repr(v) )
    return "( {s} )".format( s=s )


def funclog(logger, level=logging.DEBUG, name=None, message=None,):
    '''
    Add logging to a function.  level is the logging
    level, name is the logger name, and message is the
    log message.  If name and message aren't specified,
    they default to the function's module and name.
    '''
    def decorate(func):
        logname = name if name else func.__module__
        logmsg = message if message else logname + "." + func.__name__


        @wraps(func)
        def wrapper(*args, **kwargs):
            call_msg =  logmsg + arglist( *args, **kwargs )
            logger.log(level, call_msg )
            print call_msg
            retval =  func(*args, **kwargs)
            ret_msg = logmsg + " returning {r}".format( r=retval )
            logger.log( level, ret_msg )
            print ret_msg
            return retval
        return wrapper
    return decorate

# Example use
logger = logging.getLogger('iapservices' )
@funclog(logger, logging.CRITICAL)
def add(x, y):
    return x + y

@funclog(logger,  logging.CRITICAL )
def usedict( n, j=0, k=1 ):
    return n + j + k

@funclog(logger, logging.CRITICAL, 'example')
def spam():
    print('Spam!')


if __name__ == '__main__':
    print add( 2, 3 )
    print usedict( 2, 3 )
    print usedict( 2, k=3 )
    spam()