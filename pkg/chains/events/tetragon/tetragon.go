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
	"time"

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
	collected  map[string][]interface{}
}

// NewStorageBackend returns a new Tekton StorageBackend that stores signatures on a TaskRun
func NewEventsBackend(ctx context.Context, logger *zap.SugaredLogger, cfg config.Config) (*tetragonAPIClient, error) {
	return &tetragonAPIClient{
		logger:    logger,
		cfg:       cfg,
		collected: make(map[string][]interface{}),
	}, nil
}

func (t *tetragonAPIClient) dial(ctx context.Context) error {
	// CHANGE THIS TO USE TLS
	//conn, err := grpc.DialContext(ctx, t.cfg.Runtime.ServerAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithBlock())
	t.logger.Info("Connecting to tetragon runtime")
	conn, err := grpc.DialContext(ctx, t.cfg.Runtime.ServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	t.logger.Info("Connected to tetragon runtime")
	t.serverConn = conn
	t.client = tetragon.NewFineGuidanceSensorsClient(conn)
	return nil
}

func (t *tetragonAPIClient) GetEvents(ctx context.Context, tr *v1beta1.TaskRun) ([]interface{}, error) {
	if t.serverConn == nil || t.client == nil {
		err := t.dial(ctx)
		if err != nil {
			return nil, err
		}
	}
	if val, ok := t.collected[tr.Name]; ok {
		return val, nil
	}
	t.logger.Infof("Start collecting runtime events for  %s", tr.Name)
	var processes []interface{}
	t.client = tetragon.NewFineGuidanceSensorsClient(t.serverConn)
	stream, err := t.client.GetEvents(ctx, &tetragon.GetEventsRequest{})
	if err != nil {
		return nil, err
	}
	// Create a timer to cancel
	stop := time.NewTicker(15 * time.Second)
	var pod *tetragon.Pod
	for {
		t.logger.Info("Reached start of the loop")
		select {
		case <-stop.C:
			//Tell the Server to close this Stream, used to clean up running on the server
			err := stream.CloseSend()
			if err != nil {
				t.logger.Fatal("Failed to close stream: ", err.Error())
			}
			t.logger.Infof("Final list of processes collected %s", processes)
			t.collected[tr.Name] = processes
			return processes, nil
		default:
			// Recieve on the stream
			res, err := stream.Recv()
			if err != nil {
				return nil, err
			}
			switch res.Event.(type) {
			case *tetragon.GetEventsResponse_ProcessExec:
				exec := res.GetProcessExec()
				if exec.Process != nil {
					pod = exec.Process.GetPod()
					if pod != nil {
						if pod.Name == tr.Status.PodName && pod.Namespace == tr.Namespace {
							processes = append(processes, exec.Process)
						}
					}
				}

			case *tetragon.GetEventsResponse_ProcessExit:
				exit := res.GetProcessExit()
				if exit.Process != nil {
					pod = exit.Process.GetPod()
					if pod != nil {
						if pod.Name == tr.Status.PodName && pod.Namespace == tr.Namespace {
							processes = append(processes, exit.Process)
						}
					}
				}
			case *tetragon.GetEventsResponse_ProcessKprobe:
				kprobe := res.GetProcessKprobe()
				if kprobe.Process != nil {
					pod = kprobe.Process.GetPod()
					if pod != nil {
						if pod.Name == tr.Status.PodName && pod.Namespace == tr.Namespace {
							processes = append(processes, kprobe.Process)
						}
					}
				}
			case *tetragon.GetEventsResponse_ProcessTracepoint:
				tp := res.GetProcessTracepoint()
				if tp.Process != nil {
					pod = tp.Process.GetPod()
					if pod != nil {
						if pod.Name == tr.Status.PodName && pod.Namespace == tr.Namespace {
							processes = append(processes, *tp.Process)
						}
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
