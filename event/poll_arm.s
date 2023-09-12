#include "textflag.h"

#define SYS__PPOLL 0x150
#define N_EVTS 0x02

// func pollBlock(fds *unix.PollFd) (err unix.Errno)
TEXT ·pollBlock(SB),NOSPLIT,$0-8
	BL  	runtime·entersyscallblock(SB)	// Call blocking SYSCALL directive from runtime package
	MOVW	$SYS__PPOLL, R7			// Prepare / perform ppoll() SYSCALL    
	MOVW	fds+0(FP), R0			// PollFDs parameter
	MOVW	$N_EVTS, R1		        // Put nFDs parameter (constant N_EVTS)
	MOVW	$0x0, R2			// Put timeout parameter (set to NULL)
	MOVW	$0x0, R3                      	// Put sigmask parameter (skip)
	SWI     $0
        CMP     $0xfffff002, R0		        // No error / EINTR
	BLS	success			        // Jump to success
	RSB     $0, R0, R0			// Negate SYSCALL errno
	MOVW	R0, err+4(FP)			// Store error code in err return value
	BL  	runtime·exitsyscall(SB)		// Finalize SYSCALL using the directive from runtime package
	RET					// Return
success:
	MOVW    $0, R0
	MOVW	R0, err+4(FP)			// Store NULL error code in err return value
	BL	runtime·exitsyscall(SB)		// Finalize SYSCALL using the directive from runtime package
	RET					// Return
