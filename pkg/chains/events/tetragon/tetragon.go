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
	"strings"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/tektoncd/chains/pkg/config"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"github.com/tektoncd/pipeline/pkg/client/clientset/versioned"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type tetragonAPIClient struct {
	logger *zap.SugaredLogger
	cfg    config.Config
	//collected map[string][]string
}

// NewStorageBackend returns a new Tekton StorageBackend that stores signatures on a TaskRun
func NewEventsBackend(ctx context.Context, logger *zap.SugaredLogger, cfg config.Config) (*tetragonAPIClient, error) {
	return &tetragonAPIClient{
		logger: logger,
		cfg:    cfg,
		//collected: make(map[string][]string),
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

func (t *tetragonAPIClient) CollectEvents(ctx context.Context, tr *v1beta1.TaskRun, pipelineclientset versioned.Interface) []string {

	conn, err := t.dial(ctx)
	if err != nil {
		t.logger.Fatal("Error on receiving events: ", err.Error())
		return nil
	}

	t.logger.Infof("Start collecting runtime events for  %s", tr.Name)

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	stream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{
		AllowList: []*tetragon.Filter{{PodRegex: []string{tr.Status.PodName},
			Namespace: []string{tr.Namespace}}}})
	if err != nil {
		t.logger.Fatal("Error on receiving events: ", err.Error())
	}

	w, err := pipelineclientset.TektonV1beta1().TaskRuns(tr.Namespace).Watch(ctx, metav1.SingleObject(metav1.ObjectMeta{
		Name:      tr.Name,
		Namespace: tr.Namespace,
	}))
	if err != nil {
		t.logger.Fatal("error watching: ", err.Error())
	}

	// Setup a timeout channel
	timeoutChan := make(chan struct{})
	go func() {
		time.Sleep(120 * time.Second)
		timeoutChan <- struct{}{}
	}()

	boolChan := make(chan bool)
	stringChan := make(chan []string)
	var wg sync.WaitGroup
	wg.Add(2)

	go streamEvents(stream, t.logger, boolChan, stringChan, &wg)

	go waitForTaskRun(ctx, t.logger, pipelineclientset, boolChan, w.ResultChan(), timeoutChan, &wg)

	processes := <-stringChan
	wg.Wait()
	close(boolChan)
	close(stringChan)
	t.Close(conn)
	return processes
}

func waitForTaskRun(ctx context.Context, logger *zap.SugaredLogger, pipelineclientset versioned.Interface, ch chan<- bool, w <-chan watch.Event, timeoutChan <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	// Wait for the condition to be true or a timeout
	for {
		select {
		case ev := <-w:
			tr := ev.Object.(*v1beta1.TaskRun)

			if tr.IsDone() {
				logger.Infof("Tr done:  %s", tr.Name)
				ch <- true
				return
			} else {
				logger.Infof("Tr not yet done:  %s", tr.Name)
				ch <- false
			}
		case <-timeoutChan:
			ch <- true
			return
		}
	}
}

func streamEvents(stream tetragon.FineGuidanceSensors_GetEventsClient, logger *zap.SugaredLogger, ch <-chan bool, chString chan<- []string, wg *sync.WaitGroup) {
	defer wg.Done()
	isDone := false
	var processes []string
	for {
		//Receive on the stream
		isDone = <-ch
		if isDone {
			break
		}
		res, err := stream.Recv()
		if err != nil {
			logger.Fatal("Error on receiving events: ", err.Error())
			//Tell the Server to close this Stream, used to clean up running on the server
			err := stream.CloseSend()
			if err != nil {
				logger.Fatal("Failed to close stream: ", err.Error())
			}
			break
		}
		stringProcess, err := eventToString(res)
		if err != nil {
			logger.Error(err)
		}
		logger.Info(stringProcess)
		processes = append(processes, stringProcess)
	}
	chString <- processes
}

func processCaps(c *tetragon.Capabilities) string {
	var caps []string

	if c == nil {
		return ""
	}

	for e := range c.Effective {
		caps = append(caps, tetragon.CapabilitiesType_name[int32(e)])
	}

	capsString := strings.Join(caps, ",")
	return capsString
}

func capTrailorPrinter(str string, caps string) string {
	if len(caps) == 0 {
		return str
	}
	padding := 0
	if len(str) < 120 {
		padding = 120 - len(str)
	}
	return fmt.Sprintf("%s %*s", str, padding, caps)
}

func processInfo(host string, process *tetragon.Process) (string, string) {
	source := host
	if process.Pod != nil {
		source = fmt.Sprint(process.Pod.Namespace, "/", process.Pod.Name)
	}
	proc := process.Binary
	caps := fmt.Sprint(processCaps(process.Cap))
	return fmt.Sprintf("%s %s", source, proc), caps
}

func eventToString(response *tetragon.GetEventsResponse) (string, error) {
	switch response.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		exec := response.GetProcessExec()
		if exec.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := "process"
		processInfo, caps := processInfo(response.NodeName, exec.Process)
		args := exec.Process.Arguments
		return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, args), caps), nil
	case *tetragon.GetEventsResponse_ProcessExit:
		exit := response.GetProcessExit()
		if exit.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := "exit"
		processInfo, caps := processInfo(response.NodeName, exit.Process)
		args := exit.Process.Arguments
		var status string
		if exit.Signal != "" {
			status = exit.Signal
		}
		return capTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, args, status), caps), nil
	case *tetragon.GetEventsResponse_ProcessKprobe:
		kprobe := response.GetProcessKprobe()
		if kprobe.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		processInfo, caps := processInfo(response.NodeName, kprobe.Process)
		switch kprobe.FunctionName {
		case "__x64_sys_write":
			event := "write"
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = kprobe.Args[0].GetFileArg().Path
			}
			bytes := ""
			if len(kprobe.Args) > 2 && kprobe.Args[2] != nil {
				bytes = fmt.Sprint(kprobe.Args[2].GetSizeArg(), " bytes")
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %v", event, processInfo, file, bytes), caps), nil
		case "__x64_sys_read":
			event := "read"
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = kprobe.Args[0].GetFileArg().Path
			}
			bytes := ""
			if len(kprobe.Args) > 2 && kprobe.Args[2] != nil {
				bytes = fmt.Sprint(kprobe.Args[2].GetSizeArg(), " bytes")
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %v", event, processInfo, file, bytes), caps), nil
		case "fd_install":
			event := "open"
			file := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil && kprobe.Args[1].GetFileArg() != nil {
				file = kprobe.Args[1].GetFileArg().Path
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, file), caps), nil
		case "__x64_sys_close":
			event := "close"
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = kprobe.Args[0].GetFileArg().Path
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, file), caps), nil
		case "__x64_sys_mount":
			event := "mount"
			src := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				src = kprobe.Args[0].GetStringArg()
			}
			dst := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				dst = kprobe.Args[1].GetStringArg()
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, src, dst), caps), nil
		case "__x64_sys_setuid":
			event := "setuid"
			uid := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				uidInt := kprobe.Args[0].GetIntArg()
				uid = string(uidInt)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, uid), caps), nil
		case "__x64_sys_clock_settime":
			event := "clock_settime"
			return capTrailorPrinter(fmt.Sprintf("%s %s", event, processInfo), caps), nil
		case "__x64_sys_pivot_root":
			event := "pivot_root"
			src := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				src = kprobe.Args[0].GetStringArg()
			}
			dst := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				dst = kprobe.Args[1].GetStringArg()
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, src, dst), caps), nil
		case "proc_exec_connector":
			event := "proc_exec_connector"
			return capTrailorPrinter(fmt.Sprintf("%s %s", event, processInfo), caps), nil
		case "__x64_sys_setns":
			netns := ""
			event := "setns"
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				netns = nsId[kprobe.Args[1].GetIntArg()]
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, netns), caps), nil
		case "tcp_connect":
			event := "connect"
			sock := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				sock = fmt.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, sock), caps), nil
		case "tcp_close":
			event := "close"
			sock := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				sock = fmt.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, sock), caps), nil
		case "tcp_sendmsg":
			event := "sendmsg"
			args := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				args = fmt.Sprintf("tcp %s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport)
			}
			bytes := int32(0)
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				bytes = kprobe.Args[1].GetIntArg()
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s bytes %d", event, processInfo, args, bytes), caps), nil
		default:
			event := "syscall"
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, kprobe.FunctionName), caps), nil
		}
	case *tetragon.GetEventsResponse_ProcessTracepoint:
		tp := response.GetProcessTracepoint()
		if tp.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		processInfo, caps := processInfo(response.NodeName, tp.Process)
		switch fmt.Sprintf("%s/%s", tp.Subsys, tp.Event) {
		case "raw_syscalls/sys_enter":
			event := "syscall"
			sysName := "unknown"
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, sysName), caps), nil
		default:
			event := "tracepoint"
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, tp.Subsys, tp.Event), caps), nil
		}
	}

	return "", fmt.Errorf("unknown event type")
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
