package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"k8s.io/client-go/rest"
)

func TestBuildRestConfig_ExplicitFields(t *testing.T) {
	k8s := &KubernetesModel{
		Host:                 types.StringValue("https://k8s.example.com:6443"),
		Token:                types.StringValue("my-token"),
		ClientCertificate:    types.StringNull(),
		ClientKey:            types.StringNull(),
		ClusterCACertificate: types.StringNull(),
		Insecure:             types.BoolValue(true),
		ConfigPath:           types.StringNull(),
		ConfigContext:        types.StringNull(),
	}

	cfg, err := buildRestConfig(k8s)
	if err != nil {
		t.Fatalf("buildRestConfig failed: %v", err)
	}

	if cfg.Host != "https://k8s.example.com:6443" {
		t.Errorf("Host = %q, want %q", cfg.Host, "https://k8s.example.com:6443")
	}
	if cfg.BearerToken != "my-token" {
		t.Errorf("BearerToken = %q, want %q", cfg.BearerToken, "my-token")
	}
	if !cfg.TLSClientConfig.Insecure {
		t.Error("Insecure should be true")
	}
}

func TestBuildRestConfig_ExplicitWithCerts(t *testing.T) {
	k8s := &KubernetesModel{
		Host:                 types.StringValue("https://k8s.example.com:6443"),
		Token:                types.StringNull(),
		ClientCertificate:    types.StringValue("cert-data"),
		ClientKey:            types.StringValue("key-data"),
		ClusterCACertificate: types.StringValue("ca-data"),
		Insecure:             types.BoolValue(false),
		ConfigPath:           types.StringNull(),
		ConfigContext:        types.StringNull(),
	}

	cfg, err := buildRestConfig(k8s)
	if err != nil {
		t.Fatalf("buildRestConfig failed: %v", err)
	}

	if string(cfg.TLSClientConfig.CertData) != "cert-data" {
		t.Errorf("CertData = %q, want %q", cfg.TLSClientConfig.CertData, "cert-data")
	}
	if string(cfg.TLSClientConfig.KeyData) != "key-data" {
		t.Errorf("KeyData = %q, want %q", cfg.TLSClientConfig.KeyData, "key-data")
	}
	if string(cfg.TLSClientConfig.CAData) != "ca-data" {
		t.Errorf("CAData = %q, want %q", cfg.TLSClientConfig.CAData, "ca-data")
	}
}

func TestBuildRestConfig_NilKubernetes(t *testing.T) {
	// When kubernetes block is nil, should fall back to default kubeconfig path.
	// This will fail if no kubeconfig exists, which is expected in CI —
	// we just verify it doesn't panic.
	_, err := buildRestConfig(nil)
	// We expect an error in test environments without kubeconfig
	if err != nil {
		t.Logf("expected error without kubeconfig: %v", err)
	}
}

func TestBuildRestConfig_EmptyHost(t *testing.T) {
	k8s := &KubernetesModel{
		Host:                 types.StringValue(""),
		Token:                types.StringNull(),
		ClientCertificate:    types.StringNull(),
		ClientKey:            types.StringNull(),
		ClusterCACertificate: types.StringNull(),
		Insecure:             types.BoolValue(false),
		ConfigPath:           types.StringNull(),
		ConfigContext:        types.StringNull(),
	}

	// Empty host should fall through to kubeconfig path
	_, err := buildRestConfig(k8s)
	if err != nil {
		t.Logf("expected error without kubeconfig: %v", err)
	}
}

func TestNew(t *testing.T) {
	factory := New("1.0.0")
	p := factory()
	if p == nil {
		t.Fatal("New() returned nil provider")
	}

	kp, ok := p.(*KubesealProvider)
	if !ok {
		t.Fatal("New() did not return *KubesealProvider")
	}
	if kp.version != "1.0.0" {
		t.Errorf("version = %q, want %q", kp.version, "1.0.0")
	}
}

func TestBuildRestConfig_HostNullFallsToKubeconfig(t *testing.T) {
	k8s := &KubernetesModel{
		Host:                 types.StringNull(),
		Token:                types.StringNull(),
		ClientCertificate:    types.StringNull(),
		ClientKey:            types.StringNull(),
		ClusterCACertificate: types.StringNull(),
		Insecure:             types.BoolValue(false),
		ConfigPath:           types.StringValue("/nonexistent/kubeconfig"),
		ConfigContext:        types.StringNull(),
	}

	_, err := buildRestConfig(k8s)
	if err == nil {
		t.Error("expected error with nonexistent kubeconfig path")
	}
}

// Verify rest.Config is a valid type we can work with
func TestRestConfigType(t *testing.T) {
	cfg := &rest.Config{
		Host:        "https://example.com",
		BearerToken: "token",
	}
	if cfg.Host != "https://example.com" {
		t.Error("rest.Config not working as expected")
	}
}
