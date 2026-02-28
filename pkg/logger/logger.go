package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

// Level represents log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	}
	return "UNKNOWN"
}

// Logger wraps standard log with leveled methods.
type Logger struct {
	logger *log.Logger
	level  Level
}

// New creates a new Logger writing to stdout with INFO level.
func New() *Logger {
	return NewWithWriter(os.Stdout, LevelInfo)
}

// NewWithWriter creates a Logger writing to w.
func NewWithWriter(w io.Writer, level Level) *Logger {
	return &Logger{
		logger: log.New(w, "", 0),
		level:  level,
	}
}

func (l *Logger) log(level Level, format string, args ...any) {
	if level < l.level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	l.logger.Printf("[%s] [%s] %s", timestamp, level, msg)
	if level == LevelFatal {
		os.Exit(1)
	}
}

func (l *Logger) Debug(msg string)                        { l.log(LevelDebug, "%s", msg) }
func (l *Logger) Debugf(format string, args ...any)      { l.log(LevelDebug, format, args...) }
func (l *Logger) Info(msg string)                         { l.log(LevelInfo, "%s", msg) }
func (l *Logger) Infof(format string, args ...any)        { l.log(LevelInfo, format, args...) }
func (l *Logger) Warn(msg string)                         { l.log(LevelWarn, "%s", msg) }
func (l *Logger) Warnf(format string, args ...any)        { l.log(LevelWarn, format, args...) }
func (l *Logger) Error(msg string)                        { l.log(LevelError, "%s", msg) }
func (l *Logger) Errorf(format string, args ...any)       { l.log(LevelError, format, args...) }
func (l *Logger) Fatal(msg string)                        { l.log(LevelFatal, "%s", msg) }
func (l *Logger) Fatalf(format string, args ...any)       { l.log(LevelFatal, format, args...) }
