/*
Copyright 2022 The Tekton Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tetragon

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/tektoncd/chains/pkg/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type tetragonAPIClient struct {
	serverConn *grpc.ClientConn
	client     tetragon.FineGuidanceSensorsClient
	logger     *zap.SugaredLogger
	cfg        config.Config
}

// NewStorageBackend returns a new Tekton StorageBackend that stores signatures on a TaskRun
func NewEventsBackend(ctx context.Context, logger *zap.SugaredLogger, cfg config.Config) (*tetragonAPIClient, error) {
	return &tetragonAPIClient{
		logger: logger,
		cfg:    cfg,
	}, nil
}

func (t *tetragonAPIClient) dial(ctx context.Context) error {
	// CHANGE THIS TO USE TLS
	//conn, err := grpc.DialContext(ctx, t.cfg.Runtime.ServerAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithBlock())
	t.logger.Info("Connecting to tetragon runtime")
	conn, err := grpc.DialContext(ctx, t.cfg.Runtime.ServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return err
	}
	t.logger.Info("Connected to tetragon runtime")
	t.serverConn = conn
	t.client = tetragon.NewFineGuidanceSensorsClient(conn)
	return nil
}

func (t *tetragonAPIClient) GetEvents(ctx context.Context, tr *v1beta1.TaskRun) error {
	if t.serverConn == nil || t.client == nil {
		t.dial(ctx)
	}
	stream, err := t.client.GetEvents(ctx, &tetragon.GetEventsRequest{})
	if err != nil {
		return err
	}
	var pod *tetragon.Pod
	for {
		res, err := stream.Recv()
		if err != nil {
			return err
		}
		switch res.Event.(type) {
		case *tetragon.GetEventsResponse_ProcessExec:
			exec := res.GetProcessExec()
			if exec.Process != nil {
				pod = exec.Process.GetPod()
				if pod != nil {
					if pod.Name == tr.Status.PodName && pod.Namespace == tr.Namespace {
					}
				}
			}

		case *tetragon.GetEventsResponse_ProcessExit:
			exit := res.GetProcessExit()
			if exit.Process != nil {
				pod = exit.Process.GetPod()
				if pod != nil {
					if pod.Name == tr.Status.PodName && pod.Namespace == tr.Namespace {
					}
				}
			}
		case *tetragon.GetEventsResponse_ProcessKprobe:
			kprobe := res.GetProcessKprobe()
			if kprobe.Process != nil {
				pod = kprobe.Process.GetPod()
				if pod != nil {
					if pod.Name == tr.Status.PodName && pod.Namespace == tr.Namespace {
					}
				}
			}
		case *tetragon.GetEventsResponse_ProcessTracepoint:
			tp := res.GetProcessTracepoint()
			if tp.Process != nil {
				pod = tp.Process.GetPod()
				if pod != nil {
					if pod.Name == tr.Status.PodName && pod.Namespace == tr.Namespace {
					}
				}
			}
		}
	}
}

func (t *tetragonAPIClient) Close() error {
	err := t.serverConn.Close()
	if err != nil {
		return err
	}
	return nil
}
