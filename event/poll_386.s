#include "textflag.h"

#define INVOKE_SYSCALL INT $0x80
#define SYS__PPOLL 0x135

// func pollBlock(fds *unix.PollFd, nfds int) (err syscall.Errno)
TEXT ·pollBlock(SB),NOSPLIT,$0-12
	CALL  	runtime·entersyscallblock(SB)	// Call blocking SYSCALL directive from runtime package
	MOVL	$SYS__PPOLL, AX			// Prepare / perform ppoll() SYSCALL    
	MOVL	fds+0(FP), BX			// PollFDs parameter
	MOVL	nfds+4(FP), CX		        // Put nFDs parameter
	MOVL	$0x0, DX			// Put timeout parameter (set to NULL)
	MOVL	$0x0, SI                      	// Put sigmask parameter (skip)
	INVOKE_SYSCALL
	CMPL    AX, $0xfffff002		        // No error / EINTR
	JLS     success			        // Jump to success
	NEGL    AX				// Negate SYSCALL errno
	MOVL	AX, err+8(FP)			// Store error code in err return value
	CALL  	runtime·exitsyscall(SB)		// Finalize SYSCALL using the directive from runtime package
	RET					// Return
success:
	MOVL	$0, err+8(FP)			// Store NULL error code in err return value
	CALL    runtime·exitsyscall(SB)		// Finalize SYSCALL using the directive from runtime package
	RET					// Return
