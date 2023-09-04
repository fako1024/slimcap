package log

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

var logger = slog.New(slog.NewTextHandler(os.Stdout, nil))

// Debug emits a simple DEBUG level log message to STDOUT
func Debug(format string, args ...any) {
	if len(args) == 0 {
		_ = logger.Handler().Handle(context.TODO(), slog.NewRecord(time.Now(), slog.LevelDebug, format, 0))
	} else {
		_ = logger.Handler().Handle(context.TODO(), slog.NewRecord(time.Now(), slog.LevelDebug, fmt.Sprintf(format, args...), 0))
	}
}

// Info emits a simple INFO level log message to STDOUT
func Info(format string, args ...any) {
	fmt.Println("in info")
	if len(args) == 0 {
		_ = logger.Handler().Handle(context.TODO(), slog.NewRecord(time.Now(), slog.LevelInfo, format, 0))
	} else {
		_ = logger.Handler().Handle(context.TODO(), slog.NewRecord(time.Now(), slog.LevelInfo, fmt.Sprintf(format, args...), 0))
	}
}

// Warn emits a simple WARNING level log message to STDOUT
func Warn(format string, args ...any) {
	if len(args) == 0 {
		_ = logger.Handler().Handle(context.TODO(), slog.NewRecord(time.Now(), slog.LevelWarn, format, 0))
	} else {
		_ = logger.Handler().Handle(context.TODO(), slog.NewRecord(time.Now(), slog.LevelWarn, fmt.Sprintf(format, args...), 0))
	}
}

// Error emits a simple ERROR level log message to STDOUT
func Error(format string, args ...any) {
	if len(args) == 0 {
		_ = logger.Handler().Handle(context.TODO(), slog.NewRecord(time.Now(), slog.LevelError, format, 0))
	} else {
		_ = logger.Handler().Handle(context.TODO(), slog.NewRecord(time.Now(), slog.LevelError, fmt.Sprintf(format, args...), 0))
	}
}

// Fatal emits a simple FATAL level log message to STDOUT, then exits
func Fatal(format string, args ...any) {
	if len(args) == 0 {
		_ = logger.Handler().Handle(context.TODO(), slog.NewRecord(time.Now(), slog.Level(12), format, 0))
	} else {
		_ = logger.Handler().Handle(context.TODO(), slog.NewRecord(time.Now(), slog.Level(12), fmt.Sprintf(format, args...), 0))
	}
	os.Exit(1)
}

// enumeration of level keys (for performance. See Init's replaceFunc)
const (
	debugLevel = "debug"
	infoLevel  = "info"
	warnLevel  = "warn"
	errorLevel = "error"
	fatalLevel = "fatal"
)

// LevelFromString returns an slog.Level if the string matches one
// of the level's string descriptions. Otherwise the level LevelUnknown
// is returned (which won't be processed by the logger as a valid level)
func LevelFromString(lvl string) slog.Level {
	switch strings.ToLower(lvl) {
	case debugLevel:
		return slog.LevelDebug
	case infoLevel:
		return slog.LevelInfo
	case warnLevel:
		return slog.LevelWarn
	case errorLevel:
		return slog.LevelError
	case fatalLevel:
		return slog.Level(12)
	}
	return slog.Level(-255)
}

// SetLevel sets the default log level to the level provided via string
func SetLevel(lvl string) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: LevelFromString(lvl)})))
}
