#
# PREBOOT
# 
# GuidePoint Security LLC
#
# Threat and Attack Simulation Team
#
import sys
import logging
import colorama

class PrebootLogger( logging.Formatter ):
    """
    Custom logger that adds a bullet to the front of the message type.
    """
    def __init__( self ):
        self.Formatter.__init__( self, f'%(bullet)s %(message)s', None )

    def format( self, record ):
        if record.levelno == logging.INFO:
            record.bullet = f'{colorama.Fore.BLUE}[*]{colorama.Style.RESET_ALL}'
        elif record.levelno == logging.DEBUG:
            record.bullet = f'{colorama.Fore.CYAN}[?]{colorama.Style.RESET_ALL}'
        elif record.levelno == logging.WARNING:
            record.bullet = f'{colorama.Fore.YELLOW}[!]{colorama.Style.RESET_ALL}'
        else:
            record.bullet = f'{colorama.Fore.RED}[-]{colorama.Style.RESET_ALL}'

        # format the message
        return logging.Formatter.format( self, record )

class PrebootLoggerWithTimestamp( PrebootLogger ):
    """
    Custom logger tht adds a bullet and a timestamp to the front of the message type.
    """
    def __init__( self ):
        logging.Formatter.__init__( self, '[%(asctime)-15s] %(bullet)s %(message)s', None )

    def formatTime( self, record, datefmt = None ):
        return PrebootLogger.formatTime( self, record, datefmt="%Y-%m-%d %H:%M:%S" )


def init_log( debug = False ):
    """
    Initialiazes the logger
    """
    # initialize the stdout handler
    handler = logging.StreamHandler( sys.stdout );

    # format the buffer with a timestamp
    handler.setFormatter( PrebootLoggerWithTimestamp() )

    # add the handler
    logging.getLogger().addHandler( handler )

    if debug:
        # set the debug output
        logging.getLogger().setLevel( logging.DEBUG )
    else:
        logging.getLogger().setLevel( logging.INFO )

