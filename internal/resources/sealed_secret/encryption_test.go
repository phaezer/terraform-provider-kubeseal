package sealed_secret

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	sscrypto "github.com/bitnami-labs/sealed-secrets/pkg/crypto"
)

func TestParseScopeString(t *testing.T) {
	tests := []struct {
		input    string
		expected ssv1alpha1.SealingScope
	}{
		{"strict", ssv1alpha1.StrictScope},
		{"Strict", ssv1alpha1.StrictScope},
		{"STRICT", ssv1alpha1.StrictScope},
		{"namespace-wide", ssv1alpha1.NamespaceWideScope},
		{"Namespace-Wide", ssv1alpha1.NamespaceWideScope},
		{"cluster-wide", ssv1alpha1.ClusterWideScope},
		{"Cluster-Wide", ssv1alpha1.ClusterWideScope},
		{"", ssv1alpha1.StrictScope},
		{"unknown", ssv1alpha1.StrictScope},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := parseScopeString(tc.input)
			if result != tc.expected {
				t.Errorf("parseScopeString(%q) = %d, want %d", tc.input, result, tc.expected)
			}
		})
	}
}

func TestSecretDataHash(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		data := map[string]string{"b": "2", "a": "1", "c": "3"}
		h1 := secretDataHash(data)
		h2 := secretDataHash(data)
		if h1 != h2 {
			t.Errorf("hash not deterministic: %s != %s", h1, h2)
		}
	})

	t.Run("order independent", func(t *testing.T) {
		d1 := map[string]string{"a": "1", "b": "2"}
		d2 := map[string]string{"b": "2", "a": "1"}
		if secretDataHash(d1) != secretDataHash(d2) {
			t.Error("hash should be order-independent")
		}
	})

	t.Run("different data different hash", func(t *testing.T) {
		d1 := map[string]string{"a": "1"}
		d2 := map[string]string{"a": "2"}
		if secretDataHash(d1) == secretDataHash(d2) {
			t.Error("different data should produce different hashes")
		}
	})

	t.Run("different keys different hash", func(t *testing.T) {
		d1 := map[string]string{"a": "1"}
		d2 := map[string]string{"b": "1"}
		if secretDataHash(d1) == secretDataHash(d2) {
			t.Error("different keys should produce different hashes")
		}
	})

	t.Run("empty map", func(t *testing.T) {
		h := secretDataHash(map[string]string{})
		if h == "" {
			t.Error("empty map should still produce a hash")
		}
	})

	t.Run("no key-value boundary collision", func(t *testing.T) {
		// Ensure "a\x00b" key with "c" value differs from "a" key with "b\x00c" value
		d1 := map[string]string{"ab": "c"}
		d2 := map[string]string{"a": "bc"}
		if secretDataHash(d1) == secretDataHash(d2) {
			t.Error("key-value boundary should prevent collisions")
		}
	})
}

func TestSealSecret(t *testing.T) {
	privKey, _, err := sscrypto.GeneratePrivateKeyAndCert(2048, 24*time.Hour, "test")
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	pubKey := &privKey.PublicKey

	t.Run("basic seal", func(t *testing.T) {
		ss, err := sealSecret(
			"my-secret", "default", "Opaque",
			ssv1alpha1.StrictScope,
			map[string]string{"username": "admin", "password": "secret"},
			nil, nil, pubKey,
		)
		if err != nil {
			t.Fatalf("sealSecret failed: %v", err)
		}

		if ss.Name != "my-secret" {
			t.Errorf("name = %q, want %q", ss.Name, "my-secret")
		}
		if ss.Namespace != "default" {
			t.Errorf("namespace = %q, want %q", ss.Namespace, "default")
		}
		if ss.APIVersion != "bitnami.com/v1alpha1" {
			t.Errorf("apiVersion = %q, want %q", ss.APIVersion, "bitnami.com/v1alpha1")
		}
		if ss.Kind != "SealedSecret" {
			t.Errorf("kind = %q, want %q", ss.Kind, "SealedSecret")
		}
		if len(ss.Spec.EncryptedData) != 2 {
			t.Errorf("encrypted data has %d keys, want 2", len(ss.Spec.EncryptedData))
		}
		if _, ok := ss.Spec.EncryptedData["username"]; !ok {
			t.Error("encrypted data missing 'username' key")
		}
		if _, ok := ss.Spec.EncryptedData["password"]; !ok {
			t.Error("encrypted data missing 'password' key")
		}
	})

	t.Run("encrypted values are base64", func(t *testing.T) {
		ss, err := sealSecret(
			"test", "ns", "Opaque",
			ssv1alpha1.StrictScope,
			map[string]string{"key": "value"},
			nil, nil, pubKey,
		)
		if err != nil {
			t.Fatalf("sealSecret failed: %v", err)
		}

		for k, v := range ss.Spec.EncryptedData {
			if _, err := base64.StdEncoding.DecodeString(v); err != nil {
				t.Errorf("encrypted data[%q] is not valid base64: %v", k, err)
			}
		}
	})

	t.Run("re-encryption produces different ciphertext", func(t *testing.T) {
		data := map[string]string{"key": "value"}
		ss1, _ := sealSecret("test", "ns", "Opaque", ssv1alpha1.StrictScope, data, nil, nil, pubKey)
		ss2, _ := sealSecret("test", "ns", "Opaque", ssv1alpha1.StrictScope, data, nil, nil, pubKey)

		if ss1.Spec.EncryptedData["key"] == ss2.Spec.EncryptedData["key"] {
			t.Error("re-encryption should produce different ciphertext (random session key)")
		}
	})

	t.Run("labels applied to template", func(t *testing.T) {
		labels := map[string]string{"app": "test", "env": "dev"}
		ss, err := sealSecret("test", "ns", "Opaque", ssv1alpha1.StrictScope,
			map[string]string{"k": "v"}, labels, nil, pubKey)
		if err != nil {
			t.Fatalf("sealSecret failed: %v", err)
		}
		for k, v := range labels {
			if ss.Spec.Template.Labels[k] != v {
				t.Errorf("template label %q = %q, want %q", k, ss.Spec.Template.Labels[k], v)
			}
		}
	})

	t.Run("annotations applied to template", func(t *testing.T) {
		annotations := map[string]string{"note": "test"}
		ss, err := sealSecret("test", "ns", "Opaque", ssv1alpha1.StrictScope,
			map[string]string{"k": "v"}, nil, annotations, pubKey)
		if err != nil {
			t.Fatalf("sealSecret failed: %v", err)
		}
		for k, v := range annotations {
			if ss.Spec.Template.Annotations[k] != v {
				t.Errorf("template annotation %q = %q, want %q", k, ss.Spec.Template.Annotations[k], v)
			}
		}
	})

	t.Run("secret type preserved", func(t *testing.T) {
		ss, err := sealSecret("test", "ns", "kubernetes.io/tls", ssv1alpha1.StrictScope,
			map[string]string{"tls.crt": "cert", "tls.key": "key"}, nil, nil, pubKey)
		if err != nil {
			t.Fatalf("sealSecret failed: %v", err)
		}
		if string(ss.Spec.Template.Type) != "kubernetes.io/tls" {
			t.Errorf("secret type = %q, want %q", ss.Spec.Template.Type, "kubernetes.io/tls")
		}
	})

	t.Run("namespace-wide scope annotation", func(t *testing.T) {
		ss, err := sealSecret("test", "ns", "Opaque", ssv1alpha1.NamespaceWideScope,
			map[string]string{"k": "v"}, nil, nil, pubKey)
		if err != nil {
			t.Fatalf("sealSecret failed: %v", err)
		}
		if ss.Annotations[ssv1alpha1.SealedSecretNamespaceWideAnnotation] != "true" {
			t.Error("namespace-wide annotation not set")
		}
	})

	t.Run("cluster-wide scope annotation", func(t *testing.T) {
		ss, err := sealSecret("test", "ns", "Opaque", ssv1alpha1.ClusterWideScope,
			map[string]string{"k": "v"}, nil, nil, pubKey)
		if err != nil {
			t.Fatalf("sealSecret failed: %v", err)
		}
		if ss.Annotations[ssv1alpha1.SealedSecretClusterWideAnnotation] != "true" {
			t.Error("cluster-wide annotation not set")
		}
	})

	t.Run("strict scope has no wide annotations", func(t *testing.T) {
		ss, err := sealSecret("test", "ns", "Opaque", ssv1alpha1.StrictScope,
			map[string]string{"k": "v"}, nil, nil, pubKey)
		if err != nil {
			t.Fatalf("sealSecret failed: %v", err)
		}
		if _, ok := ss.Annotations[ssv1alpha1.SealedSecretNamespaceWideAnnotation]; ok {
			t.Error("strict scope should not have namespace-wide annotation")
		}
		if _, ok := ss.Annotations[ssv1alpha1.SealedSecretClusterWideAnnotation]; ok {
			t.Error("strict scope should not have cluster-wide annotation")
		}
	})
}

func TestSealedSecretToJSON(t *testing.T) {
	privKey, _, err := sscrypto.GeneratePrivateKeyAndCert(2048, 24*time.Hour, "test")
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	ss, err := sealSecret("test", "default", "Opaque", ssv1alpha1.StrictScope,
		map[string]string{"key": "value"}, nil, nil, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("sealSecret failed: %v", err)
	}

	jsonStr, err := sealedSecretToJSON(ss)
	if err != nil {
		t.Fatalf("sealedSecretToJSON failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify key fields
	if parsed["apiVersion"] != "bitnami.com/v1alpha1" {
		t.Errorf("apiVersion = %v, want bitnami.com/v1alpha1", parsed["apiVersion"])
	}
	if parsed["kind"] != "SealedSecret" {
		t.Errorf("kind = %v, want SealedSecret", parsed["kind"])
	}

	// Verify metadata
	metadata := parsed["metadata"].(map[string]interface{})
	if metadata["name"] != "test" {
		t.Errorf("name = %v, want test", metadata["name"])
	}
	if metadata["namespace"] != "default" {
		t.Errorf("namespace = %v, want default", metadata["namespace"])
	}

	// Verify spec.encryptedData exists
	spec := parsed["spec"].(map[string]interface{})
	encData := spec["encryptedData"].(map[string]interface{})
	if _, ok := encData["key"]; !ok {
		t.Error("encryptedData missing 'key'")
	}
}

func TestSealedSecretToYAML(t *testing.T) {
	privKey, _, err := sscrypto.GeneratePrivateKeyAndCert(2048, 24*time.Hour, "test")
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	ss, err := sealSecret("test", "default", "Opaque", ssv1alpha1.StrictScope,
		map[string]string{"key": "value"}, nil, nil, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("sealSecret failed: %v", err)
	}

	yamlStr, err := sealedSecretToYAML(ss)
	if err != nil {
		t.Fatalf("sealedSecretToYAML failed: %v", err)
	}

	if !strings.Contains(yamlStr, "apiVersion: bitnami.com/v1alpha1") {
		t.Error("YAML missing apiVersion")
	}
	if !strings.Contains(yamlStr, "kind: SealedSecret") {
		t.Error("YAML missing kind")
	}
	if !strings.Contains(yamlStr, "encryptedData:") {
		t.Error("YAML missing encryptedData")
	}
	if !strings.Contains(yamlStr, "name: test") {
		t.Error("YAML missing name")
	}
}
