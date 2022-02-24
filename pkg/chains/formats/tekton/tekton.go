/*
Copyright 2020 The Tekton Authors
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

package tekton

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/tektoncd/chains/pkg/chains/formats"
	"github.com/tektoncd/chains/pkg/chains/spire"
	"github.com/tektoncd/chains/pkg/config"
	"go.uber.org/zap"

	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
)

// Tekton is a formatter that just captures the TaskRun Status with no modifications.
type Tekton struct {
	logger           *zap.SugaredLogger
	spireEnabled     bool
	spireSocket      string
	spireWorkloadAPI *spire.SpireWorkloadApiClient
}

func NewFormatter(cfg config.Config, l *zap.SugaredLogger) (formats.Payloader, error) {
	return &Tekton{
		logger:       l,
		spireEnabled: cfg.SPIRE.Enabled,
		spireSocket:  cfg.SPIRE.SocketPath,
	}, nil
}

// CreatePayload implements the Payloader interface.
func (i *Tekton) CreatePayload(obj interface{}) (interface{}, error) {
	var tr *v1beta1.TaskRun
	switch v := obj.(type) {
	case *v1beta1.TaskRun:
		tr = v
		if i.spireEnabled {
			ctx := context.Background()
			i.spireWorkloadAPI = spire.NewSpireWorkloadApiClient(i.spireSocket)
			i.spireWorkloadAPI.DialClient(ctx)
			if err := i.spireWorkloadAPI.Verify(tr, i.logger); err != nil {
				return nil, errors.Wrap(err, "verifying SPIRE")
			}
		}
		return v.Status, nil
	default:
		return nil, fmt.Errorf("unsupported type %s", v)
	}
}

func (i *Tekton) Type() formats.PayloadType {
	return formats.PayloadTypeTekton
}

func (i *Tekton) Wrap() bool {
	return false
}
