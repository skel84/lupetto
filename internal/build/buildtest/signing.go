package buildtest

import (
	"bytes"
	"context"
	"strings"
)

const CosignKey = "/synthetic/" + SigningCanary + "/key"

const CosignConfig = "/synthetic/" + SigningCanary + "/config"

const SigningCanary = "synthetic-cosign-secret-never-retain"

type CancelOnStageWriter struct {
	Output *bytes.Buffer
	Cancel context.CancelFunc
	Stage  string
}

func (w CancelOnStageWriter) Write(data []byte) (int, error) {
	n, err := w.Output.Write(data)
	if strings.Contains(string(data), "lupetto: "+w.Stage+"\n") {
		w.Cancel()
	}
	return n, err
}
