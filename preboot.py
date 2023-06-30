#
# PREBOOT
# 
# GuidePoint Security LLC
#
# Threat and Attack Simulation Team
#
import re
import click
import pathlib
import importlib

@click.group()
def preboot():
    """
    A toolkit for conducting pre-boot attacks using the framework from @d_olex 
    and a SP605 FPGA. Useful for unlocking enterprise and consumer devices 
    that are not based upon 'Secure Core' or developed by Apple.

    Slack: @austin.hudson
    """
    pass

if __name__ in '__main__':
    Dir = pathlib.Path( "lib/cmd" );

    # loop through each directory
    for ModPth in Dir.glob( '*.py' ):
        # pull the module name
        Nam = re.sub( f'/', '.', str( ModPth ) ).rpartition( '.py' )[0]

        # import the module
        Mod = importlib.import_module( Nam )

        # find any click commands
        for Atr in dir( Mod  ):
            # is a click command
            if callable( getattr( Mod, Atr ) ) and type( getattr( Mod, Atr ) ) is click.core.Command:    
                # add the command
                preboot.add_command( getattr( Mod, Atr ) )


    # execute the main application
    preboot()
