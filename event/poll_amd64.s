// +build !slimcap_noasm

#include "textflag.h"

#define SYS__PPOLL 0x10f
#define N_EVTS 0x02

// func pollBlock(fds *unix.PollFd) (err unix.Errno)
TEXT ·pollBlock(SB),NOSPLIT,$0-16
	CALL	runtime·entersyscallblock(SB)	// Call blocking SYSCALL directive from runtime package
	MOVQ	fds+0(FP), DI					// PollFDs parameter
	MOVQ	$N_EVTS, SI						// Put nFDs parameter (constant N_EVTS)
	MOVQ	$0x0, DX						// Put timeout parameter (set to NULL)
	MOVQ	$0x0, R10                      	// Put sigmask parameter (skip)
	MOVQ	$SYS__PPOLL, AX					// Prepare / perform ppoll() SYSCALL
	SYSCALL
	CMPQ	AX, $0xfffffffffffff002			// No error / EINTR
	JLS		success							// Jump to success
	NEGQ	AX								// Negate SYSCALL errno
	MOVQ	AX, err+8(FP)					// Store error code in err return value
	CALL	runtime·exitsyscall(SB)			// Finalize SYSCALL using the directive from runtime package
	RET										// Return
success:
	MOVQ	$0, err+8(FP)					// Store NULL error code in err return value
	CALL	runtime·exitsyscall(SB)			// Finalize SYSCALL using the directive from runtime package
	RET										// Return
