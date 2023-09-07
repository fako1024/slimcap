#include "textflag.h"

#define SYS__PPOLL 0x49

// func pollBlock(fds *unix.PollFd, nfds int) (err syscall.Errno)
TEXT ·pollBlock(SB),NOSPLIT,$0-24
	BL  	runtime·entersyscallblock(SB)	// Call blocking SYSCALL directive from runtime package
	MOVD	fds+0(FP), R0					// PollFDs parameter
	MOVD	nfds+8(FP), R1					// Put nFDs parameter
	MOVD	$0x0, R2						// Put timeout parameter (set to NULL)
	MOVD	$0x0, R3                      	// Put sigmask parameter (skip)
	MOVD	$SYS__PPOLL, R8					// Prepare / perform ppoll() SYSCALL
	SVC
	CMP     $0xfffffffffffff002, R0			// No error / EINTR
	BLS		success							// Jump to success
	NEG	    R0, R0							// Negate SYSCALL errno
	MOVD	R0, err+16(FP)					// Store error code in err return value
	BL  	runtime·exitsyscall(SB)			// Finalize SYSCALL using the directive from runtime package
	RET										// Return
success:
	MOVD	$0, err+16(FP)					// Store NULL error code in err return value
	BL	    runtime·exitsyscall(SB)			// Finalize SYSCALL using the directive from runtime package
	RET										// Return
