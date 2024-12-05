package logger

import (
	"log"
	"os"
)

// Logger provides logging functionality
type Logger struct {
	logger *log.Logger  // Underlying logger
	debug  bool         // Debug mode enabled
}

func New(debug bool) *Logger {
	return &Logger{
		logger: log.New(os.Stdout, "", log.LstdFlags),
		debug:  debug,
	}
}

func (l *Logger) Debug(format string, v ...interface{}) {
	if l.debug {
		l.logger.Printf("[DEBUG] "+format, v...)
	}
}

func (l *Logger) Info(format string, v ...interface{}) {
	l.logger.Printf("[INFO] "+format, v...)
}

func (l *Logger) Error(format string, v ...interface{}) {
	l.logger.Printf("[ERROR] "+format, v...)
} 