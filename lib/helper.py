#
# PREBOOT
# 
# GuidePoint Security LLC
#
# Threat and Attack Simulation Team
#
import click

class click_arg_hex_conv( click.ParamType ):
    """
    Converts a hexidecimal or octal argument into an integer.
    """
    name = "integer"

    def convert( self, value, param, ctx ):
        if isinstance( value, int ):
            return value

        try:
            if value[:2].lower() == "0x":
                return int(value[2:], 16)
            elif value[:1] == "0":
                return int(value, 8)
            return int(value, 10)
        except ValueError:
            self.fail(f"{value!r} is not a valid integer", param, ctx)

# A new click type that supports normal integers or hex integers
click_hex_int = click_arg_hex_conv()
