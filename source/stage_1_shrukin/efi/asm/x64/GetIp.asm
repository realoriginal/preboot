;
; PREBOOT
;
; GuidePoint Security LLC
;
; Threat and Attack Simulation Team
;
[BITS 64]

;
; Exports
;
GLOBAL	GetIp

;
; Section
;
[SECTION .text$C]

;
; Purpose:
;
; Returns the address to the entrypoint of itself.
;
GetIp:
	; execute the next instruction
	call	get_next_ptr
	
	get_next_ptr:
	; capture the return address
	pop	rax
	
	; subtract the difference from get_next_ptr - GetIp
	sub	rax, 5

	; return the adress
	ret

Leave:
	; stub to identify the end of the compiled code
	db 'ENDOFCODE'
