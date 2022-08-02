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

package events

import (
	"context"

	"github.com/tektoncd/chains/pkg/chains/events/tetragon"
	"github.com/tektoncd/chains/pkg/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"github.com/tektoncd/pipeline/pkg/client/clientset/versioned"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// ControllerAPIClient interface maps to the spire controller API to interact with spire
type RuntimeAPI interface {
	CollectEvents(ctx context.Context, tr *v1beta1.TaskRun, pipelineclientset versioned.Interface) []string
	Close(conn *grpc.ClientConn) error
	//GetEvents(tr *v1beta1.TaskRun) []string
}

// InitializeBackends creates and initializes every configured storage backend.
func InitializeRuntime(ctx context.Context, logger *zap.SugaredLogger, cfg config.Config) (RuntimeAPI, error) {

	tetragon, err := tetragon.NewEventsBackend(ctx, logger, cfg)
	if err != nil {
		return nil, err
	}
	return tetragon, nil
}
