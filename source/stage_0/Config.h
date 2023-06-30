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

#define DMA_STATUS_STAGE_1		1
#define DMA_STATUS_STAGE_2		2
#define DMA_STATUS_STAGE_3		3
#define DMA_STATUS_STAGE_4		4

typedef struct __attribute__(( packed ))
{
	UINT8	DmaStatus;
	UINT32	ErrorCode;
	UINT64	ShellCode;
} DMA_STATUS, *PDMA_STATUS ;

typedef struct __attribute__(( packed ))
{
	UINT64		LocateProtocol;
	UINT64		EfiSystemTable;
	UINT64		EfiShellLength;
	PDMA_STATUS	DmaStatus;
} DMA_CONFIG, *PDMA_CONFIG ;
