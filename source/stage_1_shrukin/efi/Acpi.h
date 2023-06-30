/*!
 *
 * PREBOOT
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

/*!
 *
 * Purpose:
 *
 * Looks for the ACPI DMAR table and wipes the
 * flags field.
 *
!*/
D_SEC( B ) EFI_STATUS AcpiEnableDma( EFI_SYSTEM_TABLE* SystemTable );
