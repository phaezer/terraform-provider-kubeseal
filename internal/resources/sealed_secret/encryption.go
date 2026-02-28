package sealed_secret

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/kubeseal"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	sigyaml "sigs.k8s.io/yaml"
)

func init() {
	_ = ssv1alpha1.AddToScheme(scheme.Scheme)
}

// fetchCertificate retrieves the sealing certificate from the sealed-secrets controller
// and parses it into an RSA public key.
func fetchCertificate(ctx context.Context, restConfig *rest.Config, namespace, name string) (*rsa.PublicKey, error) {
	cfg := rest.CopyConfig(restConfig)
	cfg.AcceptContentTypes = "application/x-pem-file, */*"

	client, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating Kubernetes client: %w", err)
	}

	svc, err := client.Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting sealed-secrets service %s/%s: %w", namespace, name, err)
	}

	if len(svc.Spec.Ports) == 0 {
		return nil, fmt.Errorf("service %s/%s has no ports", namespace, name)
	}
	portName := svc.Spec.Ports[0].Name

	certStream, err := client.Services(namespace).ProxyGet("http", name, portName, "/v1/cert.pem", nil).Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching certificate from controller: %w", err)
	}
	defer certStream.Close()

	pubKey, err := kubeseal.ParseKey(certStream)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	return pubKey, nil
}

// sealSecret encrypts the given secret data into a SealedSecret object.
func sealSecret(
	name, namespace, secretType string,
	scope ssv1alpha1.SealingScope,
	data map[string]string,
	labels, annotations map[string]string,
	pubKey *rsa.PublicKey,
) (*ssv1alpha1.SealedSecret, error) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: map[string]string{},
		},
		Type:       v1.SecretType(secretType),
		StringData: data,
	}

	// Set scope annotations on the secret so NewSealedSecret picks them up
	secret.Annotations = ssv1alpha1.UpdateScopeAnnotations(secret.Annotations, scope)

	codecs := scheme.Codecs
	ss, err := ssv1alpha1.NewSealedSecret(codecs, pubKey, secret)
	if err != nil {
		return nil, fmt.Errorf("sealing secret: %w", err)
	}

	// Apply user-provided labels and annotations to the template
	if labels != nil {
		if ss.Spec.Template.Labels == nil {
			ss.Spec.Template.Labels = map[string]string{}
		}
		for k, v := range labels {
			ss.Spec.Template.Labels[k] = v
		}
	}
	if annotations != nil {
		if ss.Spec.Template.Annotations == nil {
			ss.Spec.Template.Annotations = map[string]string{}
		}
		for k, v := range annotations {
			ss.Spec.Template.Annotations[k] = v
		}
	}

	// Set API version and kind for proper serialization
	ss.APIVersion = "bitnami.com/v1alpha1"
	ss.Kind = "SealedSecret"

	return ss, nil
}

// sealedSecretToJSON serializes a SealedSecret to pretty-printed JSON.
func sealedSecretToJSON(ss *ssv1alpha1.SealedSecret) (string, error) {
	data, err := json.MarshalIndent(ss, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling SealedSecret to JSON: %w", err)
	}
	return string(data), nil
}

// sealedSecretToYAML serializes a SealedSecret to YAML.
func sealedSecretToYAML(ss *ssv1alpha1.SealedSecret) (string, error) {
	jsonData, err := json.Marshal(ss)
	if err != nil {
		return "", fmt.Errorf("marshaling SealedSecret to JSON: %w", err)
	}
	yamlData, err := sigyaml.JSONToYAML(jsonData)
	if err != nil {
		return "", fmt.Errorf("converting JSON to YAML: %w", err)
	}
	return string(yamlData), nil
}

// parseScopeString converts a string scope value to the SealingScope constant.
func parseScopeString(s string) ssv1alpha1.SealingScope {
	switch strings.ToLower(s) {
	case "namespace-wide":
		return ssv1alpha1.NamespaceWideScope
	case "cluster-wide":
		return ssv1alpha1.ClusterWideScope
	default:
		return ssv1alpha1.StrictScope
	}
}

// secretDataHash computes a deterministic SHA-256 hash of the secret data map,
// used for plan stability to detect when re-encryption is actually needed.
func secretDataHash(data map[string]string) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteByte(0)
		buf.WriteString(data[k])
		buf.WriteByte(0)
	}
	h := sha256.Sum256(buf.Bytes())
	return fmt.Sprintf("%x", h)
}

// readCertificatePEM fetches the raw PEM certificate bytes from the controller.
func readCertificatePEM(ctx context.Context, restConfig *rest.Config, namespace, name string) ([]byte, error) {
	cfg := rest.CopyConfig(restConfig)
	cfg.AcceptContentTypes = "application/x-pem-file, */*"

	client, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating Kubernetes client: %w", err)
	}

	svc, err := client.Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting sealed-secrets service %s/%s: %w", namespace, name, err)
	}

	if len(svc.Spec.Ports) == 0 {
		return nil, fmt.Errorf("service %s/%s has no ports", namespace, name)
	}
	portName := svc.Spec.Ports[0].Name

	certStream, err := client.Services(namespace).ProxyGet("http", name, portName, "/v1/cert.pem", nil).Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching certificate from controller: %w", err)
	}
	defer certStream.Close()

	return io.ReadAll(certStream)
}
