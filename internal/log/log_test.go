package log_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/internal/log"
)

var supportedLevels = []log.Level{
	log.ErrorLevel,
	log.WarnLevel,
	log.InfoLevel,
	log.DebugLevel,
}

func TestLevelEnabled(t *testing.T) {
	// This can't be parallel.
	defaultLevel := log.GetLevel()
	t.Cleanup(func() {
		log.SetLevel(defaultLevel)
	})

	for _, level := range supportedLevels {
		t.Run(fmt.Sprintf("Set log level to %s", level), func(t *testing.T) {
			log.SetLevel(level)
			require.Equal(t, level, log.GetLevel())
			require.True(t, log.IsLevelEnabled(level))
		})
	}
}

func callLogHandler(ctx context.Context, level log.Level, args ...any) {
	switch level {
	case log.ErrorLevel:
		log.Error(ctx, args...)
	case log.WarnLevel:
		log.Warning(ctx, args...)
	case log.InfoLevel:
		log.Info(ctx, args...)
	case log.DebugLevel:
		log.Debug(ctx, args...)
	}
}

func callLogHandlerf(ctx context.Context, level log.Level, format string, args ...any) {
	switch level {
	case log.ErrorLevel:
		log.Errorf(ctx, format, args...)
	case log.WarnLevel:
		log.Warningf(ctx, format, args...)
	case log.InfoLevel:
		log.Infof(ctx, format, args...)
	case log.DebugLevel:
		log.Debugf(ctx, format, args...)
	}
}

func TestSetLevelHandler(t *testing.T) {
	defaultLevel := log.GetLevel()
	t.Cleanup(func() {
		log.SetLevel(defaultLevel)
		for _, level := range supportedLevels {
			log.SetLevelHandler(context.TODO(), level, nil)
		}
	})

	for _, level := range supportedLevels {
		t.Run(fmt.Sprintf("Set log handler for %s", level), func(t *testing.T) {
			handlerCalled := false
			wantArgs := []any{true, 5.5, []string{"bar"}}
			wantCtx := context.TODO()
			log.SetLevelHandler(context.TODO(), level, func(ctx context.Context, l log.Level, format string, args ...interface{}) {
				handlerCalled = true
				require.Equal(t, wantCtx, ctx)
				require.Equal(t, level, l)
				require.Equal(t, fmt.Sprint(wantArgs...), format)
			})

			log.SetLevel(level)

			callLogHandler(wantCtx, level, wantArgs...)
			require.True(t, handlerCalled)

			handlerCalled = false
			callLogHandler(wantCtx, level+1, wantArgs...)
			require.False(t, handlerCalled)

			handlerCalled = false
			log.SetLevelHandler(context.TODO(), level, nil)

			callLogHandler(wantCtx, level, wantArgs...)
			require.False(t, handlerCalled)
		})
	}

	for _, level := range supportedLevels {
		t.Run(fmt.Sprintf("Set log handler for %s, using formatting", level), func(t *testing.T) {
			handlerCalled := false
			wantArgs := []any{true, 5.5, []string{"bar"}}
			wantFormat := "Bool is %v, float is %f, array is %v"
			wantCtx := context.TODO()
			log.SetLevelHandler(context.TODO(), level, func(ctx context.Context, l log.Level, format string, args ...interface{}) {
				handlerCalled = true
				require.Equal(t, wantCtx, ctx)
				require.Equal(t, level, l)
				require.Equal(t, wantFormat, format)
				require.Equal(t, wantArgs, args)
			})

			handlerCalled = false
			callLogHandlerf(wantCtx, level, wantFormat, wantArgs...)

			handlerCalled = false
			callLogHandlerf(wantCtx, level+1, wantFormat, wantArgs...)
			require.False(t, handlerCalled)

			handlerCalled = false
			log.SetLevelHandler(context.TODO(), level, nil)

			callLogHandlerf(wantCtx, level, wantFormat, wantArgs...)
			require.False(t, handlerCalled)
		})
	}

	log.SetLevelHandler(context.TODO(), log.Level(99999999), nil)
}

func TestSetHandler(t *testing.T) {
	defaultLevel := log.GetLevel()
	t.Cleanup(func() {
		log.SetLevel(defaultLevel)
		log.SetHandler(context.TODO(), nil)
	})

	handlerCalled := false
	wantLevel := log.Level(0)
	wantArgs := []any{true, 5.5, []string{"bar"}}
	wantCtx := context.TODO()

	log.SetHandler(context.TODO(), func(ctx context.Context, l log.Level, format string, args ...interface{}) {
		handlerCalled = true
		require.Equal(t, wantCtx, ctx)
		require.Equal(t, wantLevel, l)
		require.Equal(t, fmt.Sprint(wantArgs...), format)
	})
	for _, level := range supportedLevels {
		t.Run(fmt.Sprintf("Set log handler, testing level %s", level), func(t *testing.T) {})

		wantLevel = level
		handlerCalled = false
		log.SetLevel(level)
		callLogHandler(wantCtx, level, wantArgs...)
		require.True(t, handlerCalled)

		handlerCalled = false
		log.SetLevel(level - 1)
		callLogHandler(wantCtx, level, wantArgs...)
		require.False(t, handlerCalled)
	}

	log.SetHandler(context.TODO(), nil)
	for _, level := range supportedLevels {
		t.Run(fmt.Sprintf("Set log handler, ignoring level %s", level), func(t *testing.T) {})

		wantLevel = level
		handlerCalled = false
		log.SetLevel(level)
		callLogHandler(wantCtx, level, wantArgs...)
		require.False(t, handlerCalled)
	}

	wantFormat := "Bool is %v, float is %f, array is %v"
	log.SetHandler(context.TODO(), func(ctx context.Context, l log.Level, format string, args ...interface{}) {
		handlerCalled = true
		require.Equal(t, wantCtx, ctx)
		require.Equal(t, wantLevel, l)
		require.Equal(t, wantFormat, format)
		require.Equal(t, wantArgs, args)
	})
	for _, level := range supportedLevels {
		t.Run(fmt.Sprintf("Set log handler, testing level %s", level), func(t *testing.T) {})

		wantLevel = level
		handlerCalled = false
		log.SetLevel(level)
		callLogHandlerf(wantCtx, level, wantFormat, wantArgs...)
		require.True(t, handlerCalled)

		handlerCalled = false
		log.SetLevel(level - 1)
		callLogHandlerf(wantCtx, level, wantFormat, wantArgs...)
		require.False(t, handlerCalled)
	}

	log.SetHandler(context.TODO(), nil)
	for _, level := range supportedLevels {
		t.Run(fmt.Sprintf("Set log handler, ignoring level %s", level), func(t *testing.T) {})

		wantLevel = level
		handlerCalled = false
		log.SetLevel(level)
		callLogHandlerf(wantCtx, level, wantFormat, wantArgs...)
		require.False(t, handlerCalled)
	}
}
