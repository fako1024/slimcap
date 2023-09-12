#include "textflag.h"

#define INVOKE_SYSCALL INT $0x80
#define SYS__PPOLL 0x135
#define N_EVTS 0x02

// func pollBlock(fds *unix.PollFd) (err unix.Errno)
TEXT ·pollBlock(SB),NOSPLIT,$0-8
	CALL  	runtime·entersyscallblock(SB)	// Call blocking SYSCALL directive from runtime package
	MOVL	$SYS__PPOLL, AX			// Prepare / perform ppoll() SYSCALL    
	MOVL	fds+0(FP), BX			// PollFDs parameter
	MOVL	$N_EVTS, CX		        // Put nFDs parameter (constant N_EVTS)
	MOVL	$0x0, DX			// Put timeout parameter (set to NULL)
	MOVL	$0x0, SI                      	// Put sigmask parameter (skip)
	INVOKE_SYSCALL
	CMPL    AX, $0xfffff002		        // No error / EINTR
	JLS     success			        // Jump to success
	NEGL    AX				// Negate SYSCALL errno
	MOVL	AX, err+4(FP)			// Store error code in err return value
	CALL  	runtime·exitsyscall(SB)		// Finalize SYSCALL using the directive from runtime package
	RET					// Return
success:
	MOVL	$0, err+4(FP)			// Store NULL error code in err return value
	CALL    runtime·exitsyscall(SB)		// Finalize SYSCALL using the directive from runtime package
	RET					// Return
