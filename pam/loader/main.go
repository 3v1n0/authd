package main

import (
	"context"
	"os"

	"github.com/ubuntu/authd/internal/log"
)

func main() {
	// TODO: Add option to simulate different loading types
	log.SetLevel(log.DebugLevel)

	if ret, err := StartAuthentication(Handlers{
		gdmData: exampleHandleGdmData,
	}); err != nil {
		log.Error(context.TODO(), err)
		os.Exit(ret)
	}

	os.Exit(0)
}
