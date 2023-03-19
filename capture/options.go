package capture

type GenericOptions struct {
	snapLen   int
	isPromisc bool
}

type RingBufOptions struct {
	GenericOptions
	blockSize int
	nBlocks   int
}

type Option[T any] func(*T)

func CaptureLength[T GenericOptions](snapLen int) Option[T] {
	return func(a *T) {
		switch s := any(a).(type) {
		case *GenericOptions:
			s.snapLen = snapLen
		}
	}
}

func Promiscuous[T GenericOptions](enable bool) Option[T] {
	return func(a *T) {
		switch s := any(a).(type) {
		case *GenericOptions:
			s.isPromisc = enable
		}
	}
}

func BufferSize[T RingBufOptions](blockSize, nBlocks int) Option[T] {
	return func(a *T) {
		switch s := any(a).(type) {
		case *RingBufOptions:
			// s.blockSize = pageSizeAlign(blockSize)
			s.blockSize = blockSize
			s.nBlocks = nBlocks
		}
	}
}

// type GenericOptions interface {
// 	setPromisc(enable bool)
// 	setCaptureLength(snapLen int)
// }

// type RingBufOptions interface {
// 	setBufferSize(blockSize, nBlocks int)
// }

////////////////////////

// type GenericOption func(interface{})

// // CaptureLen sets a custom capture length (a.k.a. snaplen)
// func CaptureLength(snapLen int) GenericOption {
// 	return func(o interface{}) {
// 		o.(GenericOptions).setCaptureLength(snapLen)
// 	}
// }

// // Promiscuous enables / disabled promiscuous mode
// func Promiscuous(enable bool) GenericOption {
// 	return func(o interface{}) {
// 		o.(GenericOptions).setPromisc(enable)
// 	}
// }

// type RingBufOption func(interface{})

// // BufferSize sets a custom overall buffer size
// func BufferSize(blockSize, nBlocks int) RingBufOption {
// 	return func(o interface{}) {
// 		o.(RingBufOptions).setBufferSize(blockSize, nBlocks)
// 	}
// }

// type GenericOption[T GenericOptions] func(*T)

// type RingBufOption[T RingBufOptions] func(*T)

// func CaptureLength[T GenericOptions](snapLen int) GenericOption[T] {
// 	return func(a *T) {
// 		GenericOptions(*a).setCaptureLength(snapLen)
// 	}
// }

// func Promiscuous[T GenericOptions](enable bool) GenericOption[T] {
// 	return func(a *T) {
// 		GenericOptions(*a).setPromisc(enable)
// 	}
// }

// func BufferSize[T RingBufOptions](blockSize, nBlocks int) RingBufOption[T] {
// 	return func(a *T) {
// 		RingBufOptions(*a).setBufferSize(blockSize, nBlocks)
// 	}
// }
