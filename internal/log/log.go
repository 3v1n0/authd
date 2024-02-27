// Package log is a temporary package until we forge our log structure.
package log

import (
	"context"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
)

type (
	// TextFormatter is the text formatter for the logs.
	TextFormatter = logrus.TextFormatter

	// Level is the log level for the logs.
	Level = logrus.Level

	// Handler is the log handler function.
	Handler = func(_ context.Context, _ Level, format string, args ...interface{})
)

var (
	// SetFormatter sets the standard logger formatter.
	SetFormatter = logrus.SetFormatter
	// SetLevel sets the standard logger level.
	SetLevel = logrus.SetLevel
	// SetReportCaller sets whether the standard logger will include the calling method as a field.
	SetReportCaller = logrus.SetReportCaller
)

const (
	// ErrorLevel level. Logs. Used for errors that should definitely be noted.
	// Commonly used for hooks to send errors to an error tracking service.
	ErrorLevel = logrus.ErrorLevel
	// WarnLevel level. Non-critical entries that deserve eyes.
	WarnLevel = logrus.WarnLevel
	// InfoLevel level. General operational entries about what's going on inside the application.
	InfoLevel = logrus.InfoLevel
	// DebugLevel level. Usually only enabled when debugging. Very verbose logging.
	DebugLevel = logrus.DebugLevel
)

func logFuncAdapter(logrusFunc func(args ...interface{})) Handler {
	return func(_ context.Context, _ Level, format string, args ...interface{}) {
		logrusFunc(fmt.Sprintf(format, args...))
	}
}

var defaultHandlers = map[Level]Handler{
	DebugLevel: logFuncAdapter(logrus.Debug),
	InfoLevel:  logFuncAdapter(logrus.Info),
	WarnLevel:  logFuncAdapter(logrus.Warn),
	ErrorLevel: logFuncAdapter(logrus.Error),
}
var handlers = defaultHandlers
var handlersMu = sync.RWMutex{}

// SetLevelHandler allows to define the default handler function for a given level.
func SetLevelHandler(level Level, handler Handler) {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	if handler == nil {
		h, ok := defaultHandlers[level]
		if !ok {
			return
		}
		handler = h
	}
	handlers[level] = handler
}

// SetHandler allows to define the default handler function for all log levels.
func SetHandler(handler Handler) {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	if handler == nil {
		handlers = defaultHandlers
		return
	}
	for _, level := range logrus.AllLevels {
		handlers[level] = handler
	}
}

func log(context context.Context, level Level, args ...interface{}) {
	if !logrus.IsLevelEnabled(level) {
		return
	}

	logf(context, level, fmt.Sprint(args...))
}

func logf(context context.Context, level Level, format string, args ...interface{}) {
	if !logrus.IsLevelEnabled(level) {
		return
	}

	handlersMu.RLock()
	handler := handlers[level]
	handlersMu.RUnlock()

	handler(context, level, format, args...)
}

// Debug is a temporary placeholder.
func Debug(context context.Context, args ...interface{}) {
	log(context, DebugLevel, args...)
}

// Debugf is a temporary placeholder.
func Debugf(context context.Context, format string, args ...interface{}) {
	logf(context, DebugLevel, format, args...)
}

// Info is a temporary placeholder.
func Info(context context.Context, args ...interface{}) {
	log(context, InfoLevel, args...)
}

// Warning is a temporary placeholder.
func Warning(context context.Context, args ...interface{}) {
	log(context, WarnLevel, args...)
}

// Warningf is a temporary placeholder.
func Warningf(context context.Context, format string, args ...interface{}) {
	logf(context, WarnLevel, format, args...)
}

// Error is a temporary placeholder.
func Error(context context.Context, args ...interface{}) {
	log(context, ErrorLevel, args...)
}

// Errorf is a temporary placeholder.
func Errorf(context context.Context, format string, args ...interface{}) {
	logf(context, ErrorLevel, format, args...)
}

// Infof is a temporary placeholder.
func Infof(context context.Context, format string, args ...interface{}) {
	logf(context, InfoLevel, format, args...)
}
