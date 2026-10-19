// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
)

// loadImages copies images from the local Docker store into every Kind node, so
// the cluster runs exactly what was built here without a registry. An image that
// is not in the store yet, such as a published one named through a harness knob,
// is pulled first.
//
// It drives the docker CLI, as the harness and Kind both do, rather than a Docker
// client library whose dependencies would have to agree with theirs.
func (e *environment) loadImages(ctx context.Context, refs ...string) error {
	for _, ref := range refs {
		if err := docker(ctx, "image", "inspect", ref); err == nil {
			continue
		}
		if err := docker(ctx, "pull", ref); err != nil {
			return err
		}
	}

	log.Printf("e2e: loading %v into the Kind nodes", refs)
	archivePath := filepath.Join(e.workDir, "images.tar")
	if err := docker(ctx, append([]string{"save", "-o", archivePath}, refs...)...); err != nil {
		return err
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() {
		_ = archive.Close()
	}()

	nodes, err := e.kind.ListNodes(kindClusterName)
	if err != nil {
		return fmt.Errorf("list Kind nodes: %w", err)
	}
	for _, node := range nodes {
		if _, err := archive.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := nodeutils.LoadImageArchive(node, archive); err != nil {
			return fmt.Errorf("load images into node %s: %w", node.String(), err)
		}
	}
	return nil
}

func docker(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker %v: %w\n%s", args, err, out)
	}
	return nil
}
