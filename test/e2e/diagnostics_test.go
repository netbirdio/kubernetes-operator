// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	serverLogLines = 60
	podLogLines    = 40
	eventLines     = 30
)

// requireEnv returns the environment TestMain brought up and, should the test
// fail, logs the server's log and the operator's namespace. Everything is torn
// down before the run reports, so a failure has to carry this with it.
func requireEnv(t *testing.T) *environment {
	t.Helper()
	if testEnv == nil {
		t.Fatal("the e2e environment was not bootstrapped; run the suite through TestMain with -tags e2e")
	}
	e := testEnv
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		t.Logf("netbird-server log (tail):\n%s", tail(e.srv.Logs(ctx), serverLogLines))
		t.Logf("namespace %s:\n%s", netbirdNamespace, e.describeNamespace(ctx, netbirdNamespace))
	})
	return e
}

// createNamespace creates a namespace for one test, named after prefix. When the
// test passes the namespace is deleted with it; when it fails the namespace is
// described in the test's log instead, and left for the teardown.
func (e *environment) createNamespace(t *testing.T, prefix string) string {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: prefix + "-"}}
	require.NoError(t, e.k8s.Create(t.Context(), ns))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if t.Failed() {
			t.Logf("namespace %s:\n%s", ns.Name, e.describeNamespace(ctx, ns.Name))
			return
		}
		if err := e.k8s.Delete(ctx, ns); err != nil {
			t.Logf("delete namespace %s: %v", ns.Name, err)
		}
	})
	return ns.Name
}

// describeNamespace summarizes the pods, their logs and the recent events in a
// namespace.
func (e *environment) describeNamespace(ctx context.Context, ns string) string {
	var b strings.Builder
	pods, err := e.clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&b, "list pods: %v\n", err)
	} else {
		for _, pod := range pods.Items {
			fmt.Fprintf(&b, "pod %s: %s\n", pod.Name, pod.Status.Phase)
			statuses := slices.Concat(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses)
			for _, cs := range statuses {
				fmt.Fprintf(&b, "  container %s: ready=%t restarts=%d %s\n", cs.Name, cs.Ready, cs.RestartCount, containerState(cs.State))
				fmt.Fprintf(&b, "%s\n", indent(e.podLogTail(ctx, ns, pod.Name, cs.Name, podLogLines), "    "))
			}
		}
	}

	events, err := e.clientset.CoreV1().Events(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&b, "list events: %v\n", err)
		return b.String()
	}
	items := events.Items
	slices.SortFunc(items, func(a, b corev1.Event) int {
		return cmp.Compare(eventTime(a).UnixNano(), eventTime(b).UnixNano())
	})
	if len(items) > eventLines {
		items = items[len(items)-eventLines:]
	}
	for _, ev := range items {
		fmt.Fprintf(&b, "event %s %s/%s %s: %s\n", ev.Type, ev.InvolvedObject.Kind, ev.InvolvedObject.Name, ev.Reason, ev.Message)
	}
	return b.String()
}

// podLogTail returns the last lines of a container's log, or why it could not.
func (e *environment) podLogTail(ctx context.Context, ns, pod, container string, lines int64) string {
	req := e.clientset.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{Container: container, TailLines: &lines})
	stream, err := req.Stream(ctx)
	if err != nil {
		return fmt.Sprintf("<logs unavailable: %v>", err)
	}
	defer func() {
		_ = stream.Close()
	}()
	out, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Sprintf("<logs unavailable: %v>", err)
	}
	return string(out)
}

func containerState(s corev1.ContainerState) string {
	switch {
	case s.Waiting != nil:
		return fmt.Sprintf("waiting (%s: %s)", s.Waiting.Reason, s.Waiting.Message)
	case s.Terminated != nil:
		return fmt.Sprintf("terminated (%s, exit %d)", s.Terminated.Reason, s.Terminated.ExitCode)
	case s.Running != nil:
		return "running"
	default:
		return "unknown"
	}
}

func eventTime(ev corev1.Event) time.Time {
	if !ev.LastTimestamp.IsZero() {
		return ev.LastTimestamp.Time
	}
	return ev.EventTime.Time
}

// tail returns the last n lines of a log.
func tail(log string, n int) string {
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}
