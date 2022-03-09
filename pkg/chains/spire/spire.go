/*
Copyright 2021 The Tekton Authors
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

package spire

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	"go.uber.org/zap"
	"knative.dev/pkg/apis"
)

const (
	TaskRunStatusHashAnnotation    = "tekton.dev/status-hash"
	taskRunStatusHashSigAnnotation = "tekton.dev/status-hash-sig"
	controllerSvidAnnotation       = "tekton.dev/controller-svid"
)

type SpireWorkloadApiClient struct {
	socketPath string
	client     *workloadapi.Client
}

func (w *SpireWorkloadApiClient) checkClient(ctx context.Context) error {
	if w.client == nil {
		return w.dial(ctx)
	}
	return nil
}

func (w *SpireWorkloadApiClient) dial(ctx context.Context) error {
	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+w.socketPath))
	if err != nil {
		return errors.Errorf("Spire workload API not initalized due to error: %w", err.Error())
	}
	w.client = client
	return nil
}

func NewSpireWorkloadApiClient(socket string) *SpireWorkloadApiClient {
	return &SpireWorkloadApiClient{
		socketPath: socket,
	}
}

func getTrustBundle(client *workloadapi.Client, ctx context.Context) (*x509.CertPool, error) {
	x509set, err := client.FetchX509Bundles(ctx)
	if err != nil {
		return nil, err
	}
	x509Bundle := x509set.Bundles()
	if err != nil {
		return nil, err
	}
	trustPool := x509.NewCertPool()
	for _, c := range x509Bundle[0].X509Authorities() {
		trustPool.AddCert(c)
	}
	return trustPool, nil
}

// Verify checks if the TaskRun has an SVID cert
// it then verifies the provided signatures against the cert
func (w *SpireWorkloadApiClient) Verify(ctx context.Context, tr *v1beta1.TaskRun, logger *zap.SugaredLogger) error {
	err := w.checkClient(ctx)
	if err != nil {
		return err
	}

	annotations := tr.Status.Annotations
	if !tr.Status.GetCondition(apis.ConditionType("Verified")).IsTrue() {
		return errors.New("taskrun status condition not verified. Spire taskrun results verification failure")
	}
	logger.Info("Successfully verified Taskrun results via taskrun status condition")

	// get trust bundle from spire server
	trust, err := getTrustBundle(w.client, context.Background())
	if err != nil {
		return err
	}

	// verify controller SVID
	svid, ok := annotations[controllerSvidAnnotation]
	if !ok {
		return errors.New("No SVID found")
	}
	block, _ := pem.Decode([]byte(svid))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid SVID: %w", err)
	}

	// verify certificate root of trust
	if err := verifyCertificateTrust(cert, trust); err != nil {
		return err
	}
	logger.Infof("Successfully verified certificate %s against SPIRE", svid)

	if err := verifySignature(cert.PublicKey, annotations); err != nil {
		return err
	}
	logger.Info("Successfully verified signature")

	// check current status hash vs annotation status hash by controller
	if err := checkStatusInternalAnnotation(tr, annotations); err != nil {
		return err
	}
	logger.Info("Successfully verified status annotation hash matches the current taskrun status")

	return nil
}

func verifySignature(pub interface{}, annotations map[string]string) error {
	signature, ok := annotations[taskRunStatusHashSigAnnotation]
	if !ok {
		return fmt.Errorf("no signature found for %s", taskRunStatusHashSigAnnotation)
	}
	b, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	hash, ok := annotations[TaskRunStatusHashAnnotation]
	if !ok {
		return fmt.Errorf("no annotation status hash found for %s", TaskRunStatusHashAnnotation)
	}
	h := sha256.Sum256([]byte(hash))
	// Check val against sig
	switch t := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(t, h[:], b) {
			return errors.New("invalid signature verification with ecdsa.PublicKey")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(t, crypto.SHA256, h[:], b)
	case ed25519.PublicKey:
		if !ed25519.Verify(t, []byte(hash), b) {
			return errors.New("invalid signature verification with ed25519.PublicKey")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type: %s", t)
	}
}

func hashTaskrunStatusInternal(tr *v1beta1.TaskRun) (string, error) {
	s, err := json.Marshal(tr.Status.TaskRunStatusFields)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(s)), nil
}

func checkStatusInternalAnnotation(tr *v1beta1.TaskRun, annotations map[string]string) error {
	// get stored hash of status
	hash, ok := annotations[TaskRunStatusHashAnnotation]
	if !ok {
		return fmt.Errorf("no annotation status hash found for %s", TaskRunStatusHashAnnotation)
	}
	// get current hash of status
	current, err := hashTaskrunStatusInternal(tr)
	if err != nil {
		return err
	}
	if hash != current {
		return fmt.Errorf("current status hash and stored annotation hash does not match! Annotation Hash: %s, Current Status Hash: %s", hash, current)
	}
	return nil
}

func verifyCertificateTrust(cert *x509.Certificate, rootCertPool *x509.CertPool) error {
	verifyOptions := x509.VerifyOptions{
		Roots: rootCertPool,
	}
	chains, err := cert.Verify(verifyOptions)
	if len(chains) == 0 || err != nil {
		return fmt.Errorf("cert cannot be verified by provided roots")
	}
	return nil
}
