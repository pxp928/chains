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
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/tektoncd/chains/pkg/chains/provenance"
	"github.com/tektoncd/chains/pkg/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type tetragonAPIClient struct {
	logger    *zap.SugaredLogger
	cfg       config.Config
	collected map[string][]*provenance.Process
	client    tetragon.FineGuidanceSensorsClient
}

// NewStorageBackend returns a new Tekton StorageBackend that stores signatures on a TaskRun
func NewEventsBackend(ctx context.Context, logger *zap.SugaredLogger, cfg config.Config) (*tetragonAPIClient, error) {
	return &tetragonAPIClient{
		logger:    logger,
		cfg:       cfg,
		collected: make(map[string][]*provenance.Process),
	}, nil
}

func (t *tetragonAPIClient) dial(ctx context.Context) (*grpc.ClientConn, error) {
	// CHANGE THIS TO USE TLS
	//conn, err := grpc.DialContext(ctx, t.cfg.Runtime.ServerAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithBlock())
	t.logger.Info("Connecting to tetragon runtime")
	conn, err := grpc.DialContext(ctx, t.cfg.Runtime.ServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	t.logger.Info("Connected to tetragon runtime")
	return conn, nil
}

func (t *tetragonAPIClient) GetTracingPolicies(ctx context.Context) []*provenance.TracePolicy {
	sensors, err := t.client.ListSensors(ctx, &tetragon.ListSensorsRequest{})
	if err != nil {
		t.logger.Fatal("error on retrieving sensors: ", err.Error())
		return nil
	} else if sensors == nil {
		t.logger.Fatal("error: sensors is nil\n")
		return nil
	}

	tracePolicies := []*provenance.TracePolicy{}
	for _, sensor := range sensors.Sensors {
		foundPolicy := provenance.TracePolicy{}
		if sensor.Enabled {
			foundPolicy.Name = sensor.Name
			req := tetragon.PrintSensorStateRequest{Name: sensor.Name}
			res, err := t.client.PrintSensorState(ctx, &req)
			if err == nil {
				foundPolicy.Name = sensor.Name
				foundPolicy.Config = res.State
				tracePolicies = append(tracePolicies, &foundPolicy)
			} else {
				t.logger.Fatal("error getting config value for %s: %s\n", sensor, err)
			}
		}
	}
	return tracePolicies
}

func (t *tetragonAPIClient) GetEvents(tr *v1beta1.TaskRun) []*provenance.Process {
	foundProcess := t.collected[tr.Status.PodName]
	//t.collected = map[string][]*provenance.Process{}
	return foundProcess
}

func (t *tetragonAPIClient) CollectEvents(ctx context.Context) {

	conn, err := t.dial(ctx)
	if err != nil {
		t.logger.Fatal("error on receiving events: ", err.Error())
	}

	t.logger.Info("Start collecting runtime events")

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	t.client = client
	stream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{
		AllowList: []*tetragon.Filter{{Namespace: []string{t.cfg.Runtime.Namespace}}}})
	if err != nil {
		t.logger.Fatal("Error on receiving events: ", err.Error())
	}

	for {
		res, err := stream.Recv()
		if err != nil {
			t.logger.Fatal("Error on receiving events: ", err.Error())
			//Tell the Server to close this Stream, used to clean up running on the server
			err := stream.CloseSend()
			if err != nil {
				t.logger.Fatal("Failed to close stream: ", err.Error())
			}
			break
		}
		podname, process, err := eventToString(res)
		if err != nil {
			t.logger.Error(err)
		}
		t.collected[podname] = append(t.collected[podname], process)
	}
}

// func streamEvents(stream tetragon.FineGuidanceSensors_GetEventsClient, logger *zap.SugaredLogger, chEvent chan<- *tetragon.GetEventsResponse) {
// 	for {
// 		res, err := stream.Recv()
// 		if err != nil {
// 			logger.Fatal("Error on receiving events: ", err.Error())
// 			//Tell the Server to close this Stream, used to clean up running on the server
// 			err := stream.CloseSend()
// 			if err != nil {
// 				logger.Fatal("Failed to close stream: ", err.Error())
// 			}
// 			break
// 		}
// 		chEvent <- res
// 	}
// }

func processCaps(c *tetragon.Capabilities) []string {
	var caps []string

	if c == nil {
		return nil
	}

	for e := range c.Effective {
		caps = append(caps, tetragon.CapabilitiesType_name[int32(e)])
	}
	return caps
}

func getPodInfo(process *tetragon.Process) string {
	return fmt.Sprint(process.Pod.Name)
}

func eventToString(response *tetragon.GetEventsResponse) (string, *provenance.Process, error) {
	collectedProcess := &provenance.Process{}
	switch response.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessExec:

		exec := response.GetProcessExec()
		if exec.Process == nil {
			return "", nil, fmt.Errorf("process field is not set")
		}
		collectedProcess.EventType = "process"
		collectedProcess.ProcessBinary = exec.Process.Binary
		collectedProcess.Arguments = []string{exec.Process.Arguments}
		collectedProcess.Privileged = processCaps(exec.Process.Cap)
		return getPodInfo(exec.Process), collectedProcess, nil
	case *tetragon.GetEventsResponse_ProcessExit:
		exit := response.GetProcessExit()
		if exit.Process == nil {
			return "", nil, fmt.Errorf("process field is not set")
		}
		collectedProcess.EventType = "exit"
		collectedProcess.ProcessBinary = exit.Process.Binary
		collectedProcess.Arguments = []string{exit.Signal, exit.Process.Arguments}
		collectedProcess.Privileged = processCaps(exit.Process.Cap)
		return getPodInfo(exit.Process), collectedProcess, nil
	case *tetragon.GetEventsResponse_ProcessKprobe:
		kprobe := response.GetProcessKprobe()
		if kprobe.Process == nil {
			return "", nil, fmt.Errorf("process field is not set")
		}
		switch kprobe.FunctionName {
		case "__x64_sys_write":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "__x64_sys_write"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, kprobe.Args[0].GetFileArg().Path)
			}
			if len(kprobe.Args) > 2 && kprobe.Args[2] != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, fmt.Sprint(kprobe.Args[2].GetSizeArg(), " bytes"))
			}
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "__x64_sys_read":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "__x64_sys_read"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, kprobe.Args[0].GetFileArg().Path)
			}
			if len(kprobe.Args) > 2 && kprobe.Args[2] != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, fmt.Sprint(kprobe.Args[2].GetSizeArg(), " bytes"))
			}
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "fd_install":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "fd_install"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil && kprobe.Args[1].GetFileArg() != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, kprobe.Args[0].GetFileArg().Path)
			}
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "__x64_sys_close":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "__x64_sys_close"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, kprobe.Args[0].GetFileArg().Path)
			}
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "__x64_sys_mount":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "__x64_sys_mount"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, kprobe.Args[0].GetStringArg())
			}

			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, kprobe.Args[1].GetStringArg())
			}
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "__x64_sys_setuid":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "__x64_sys_setuid"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				uidInt := kprobe.Args[0].GetIntArg()
				collectedProcess.Arguments = append(collectedProcess.Arguments, string(uidInt))
			}
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "__x64_sys_clock_settime":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "__x64_sys_clock_settime"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "__x64_sys_pivot_root":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "__x64_sys_pivot_root"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, kprobe.Args[0].GetStringArg())
			}
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, kprobe.Args[1].GetStringArg())
			}
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "proc_exec_connector":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "proc_exec_connector"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "__x64_sys_setns":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "__x64_sys_setns"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, nsId[kprobe.Args[1].GetIntArg()])
			}
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "tcp_connect":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "tcp_connect"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				collectedProcess.Arguments = append(collectedProcess.Arguments, fmt.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport))
			}
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "tcp_close":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "tcp_close"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				collectedProcess.Arguments = append(collectedProcess.Arguments, fmt.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport))
			}
			return getPodInfo(kprobe.Process), collectedProcess, nil
		case "tcp_sendmsg":
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "tcp_sendmsg"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				collectedProcess.Arguments = append(collectedProcess.Arguments, fmt.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport))
			}
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				collectedProcess.Arguments = append(collectedProcess.Arguments, string(kprobe.Args[1].GetIntArg()))
			}
			return getPodInfo(kprobe.Process), collectedProcess, nil
		default:
			collectedProcess.EventType = "kprobe"
			collectedProcess.Function = "syscall"
			collectedProcess.ProcessBinary = kprobe.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(kprobe.Process.Cap)
			return getPodInfo(kprobe.Process), collectedProcess, nil
		}
	case *tetragon.GetEventsResponse_ProcessTracepoint:
		tp := response.GetProcessTracepoint()
		if tp.Process == nil {
			return "", nil, fmt.Errorf("process field is not set")
		}
		switch fmt.Sprintf("%s/%s", tp.Subsys, tp.Event) {
		case "raw_syscalls/sys_enter":
			collectedProcess.EventType = "tracepoint"
			collectedProcess.Function = "raw_syscalls/sys_enter"
			collectedProcess.ProcessBinary = tp.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(tp.Process.Cap)
			return getPodInfo(tp.Process), collectedProcess, nil
		default:
			collectedProcess.EventType = "tracepoint"
			collectedProcess.ProcessBinary = tp.Process.Binary
			collectedProcess.Arguments = []string{}
			collectedProcess.Privileged = processCaps(tp.Process.Cap)
			return getPodInfo(tp.Process), collectedProcess, nil
		}
	}

	return "", nil, fmt.Errorf("unknown event type")
}

var (
	CLONE_NEWCGROUP = 0x2000000
	CLONE_NEWIPC    = 0x8000000
	CLONE_NEWNET    = 0x40000000
	CLONE_NEWNS     = 0x20000
	CLONE_NEWPID    = 0x20000000
	CLONE_NEWTIME   = 0x80
	CLONE_NEWUSER   = 0x10000000
	CLONE_NEWUTS    = 0x4000000
)

var nsId = map[int32]string{
	int32(0):               "any",
	int32(CLONE_NEWCGROUP): "cgroup",
	int32(CLONE_NEWIPC):    "ipc",
	int32(CLONE_NEWNET):    "net",
	int32(CLONE_NEWNS):     "mnt",
	int32(CLONE_NEWPID):    "pid",
	int32(CLONE_NEWTIME):   "time",
	int32(CLONE_NEWUSER):   "user",
	int32(CLONE_NEWUTS):    "uts",
}

func (t *tetragonAPIClient) Close(conn *grpc.ClientConn) error {
	err := conn.Close()
	if err != nil {
		return err
	}
	return nil
}
