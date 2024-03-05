// Package log is a temporary package until we forge our log structure.
package log

import (
	"context"
	"fmt"
	"maps"
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
	// GetLevel gets the standard logger level.
	GetLevel = logrus.GetLevel
	// IsLevelEnabled checks if the log level is greater than the level param.
	IsLevelEnabled = logrus.IsLevelEnabled
	// SetFormatter sets the standard logger formatter.
	SetFormatter = logrus.SetFormatter
	// SetLevel sets the standard logger level.
	SetLevel = logrus.SetLevel
	// SetOutput sets the log output.
	SetOutput = logrus.SetOutput
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

type handlersMap map[Level]Handler

var defaultHandlers = handlersMap{
	DebugLevel: logFuncAdapter(logrus.Debug),
	InfoLevel:  logFuncAdapter(logrus.Info),
	WarnLevel:  logFuncAdapter(logrus.Warn),
	ErrorLevel: logFuncAdapter(logrus.Error),
}
var handlers = map[context.Context]handlersMap{}
var handlersMu = sync.RWMutex{}

func ensureHandlers(ctx context.Context) handlersMap {
	contextHandlers, ok := handlers[ctx]
	if ok {
		return contextHandlers
	}
	contextHandlers = make(map[logrus.Level]Handler)
	handlers[ctx] = contextHandlers
	return contextHandlers
}

// SetLevelHandler allows to define the default handler function for a given level.
func SetLevelHandler(ctx context.Context, level Level, handler Handler) {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	if handler == nil {
		h, ok := defaultHandlers[level]
		if !ok {
			return
		}
		handler = h
	}
	ensureHandlers(ctx)[level] = handler
}

// SetHandler allows to define the default handler function for all log levels.
func SetHandler(ctx context.Context, handler Handler) {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	ensureHandlers(ctx)
	if handler == nil {
		handlers[ctx] = maps.Clone(defaultHandlers)
		return
	}
	contextHandlers := handlers[ctx]
	for _, level := range logrus.AllLevels {
		contextHandlers[level] = handler
	}
}

func log(context context.Context, level Level, args ...interface{}) {
	if !IsLevelEnabled(level) {
		return
	}

	logf(context, level, fmt.Sprint(args...))
}

func logf(context context.Context, level Level, format string, args ...interface{}) {
	if !IsLevelEnabled(level) {
		return
	}

	handlersMu.RLock()
	contextHandlers, ok := handlers[context]
	if !ok {
		contextHandlers = defaultHandlers
	}

	handler, ok := contextHandlers[level]
	if !ok {
		handler = defaultHandlers[level]
	}
	handlersMu.RUnlock()

	if handler == nil {
		return
	}

	handler(context, level, format, args...)
}

// Debug outputs messages with the level [DebugLevel] (when that is enabled) using the
// configured logging handler.
func Debug(context context.Context, args ...interface{}) {
	log(context, DebugLevel, args...)
}

// Debugf outputs messages with the level [DebugLevel] (when that is enabled) using the
// configured logging handler.
func Debugf(context context.Context, format string, args ...interface{}) {
	logf(context, DebugLevel, format, args...)
}

// Info outputs messages with the level [InfoLevel] (when that is enabled) using the
// configured logging handler.
func Info(context context.Context, args ...interface{}) {
	log(context, InfoLevel, args...)
}

// Infof outputs messages with the level [InfoLevel] (when that is enabled) using the
// configured logging handler.
func Infof(context context.Context, format string, args ...interface{}) {
	logf(context, InfoLevel, format, args...)
}

// Warning outputs messages with the level [WarningLevel] (when that is enabled) using the
// configured logging handler.
func Warning(context context.Context, args ...interface{}) {
	log(context, WarnLevel, args...)
}

// Warningf outputs messages with the level [WarningLevel] (when that is enabled) using the
// configured logging handler.
func Warningf(context context.Context, format string, args ...interface{}) {
	logf(context, WarnLevel, format, args...)
}

// Error outputs messages with the level [ErrorLevel] (when that is enabled) using the
// configured logging handler.
func Error(context context.Context, args ...interface{}) {
	log(context, ErrorLevel, args...)
}

// Errorf outputs messages with the level [ErrorLevel] (when that is enabled) using the
// configured logging handler.
func Errorf(context context.Context, format string, args ...interface{}) {
	logf(context, ErrorLevel, format, args...)
}
