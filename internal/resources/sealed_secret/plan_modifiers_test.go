package sealed_secret

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func testMap(vals map[string]string) types.Map {
	elements := make(map[string]attr.Value, len(vals))
	for k, v := range vals {
		elements[k] = types.StringValue(v)
	}
	return types.MapValueMust(types.StringType, elements)
}

func TestInputsChanged(t *testing.T) {
	base := SealedSecretResourceModel{
		Name:        types.StringValue("test"),
		Namespace:   types.StringValue("default"),
		Type:        types.StringValue("Opaque"),
		Scope:       types.StringValue("strict"),
		SecretData:  testMap(map[string]string{"key": "value"}),
		Labels:      types.MapNull(types.StringType),
		Annotations: types.MapNull(types.StringType),
	}

	t.Run("identical models no change", func(t *testing.T) {
		if inputsChanged(base, base) {
			t.Error("identical models should not be considered changed")
		}
	})

	t.Run("name changed", func(t *testing.T) {
		modified := base
		modified.Name = types.StringValue("other")
		if !inputsChanged(modified, base) {
			t.Error("name change should be detected")
		}
	})

	t.Run("namespace changed", func(t *testing.T) {
		modified := base
		modified.Namespace = types.StringValue("other-ns")
		if !inputsChanged(modified, base) {
			t.Error("namespace change should be detected")
		}
	})

	t.Run("type changed", func(t *testing.T) {
		modified := base
		modified.Type = types.StringValue("kubernetes.io/tls")
		if !inputsChanged(modified, base) {
			t.Error("type change should be detected")
		}
	})

	t.Run("scope changed", func(t *testing.T) {
		modified := base
		modified.Scope = types.StringValue("cluster-wide")
		if !inputsChanged(modified, base) {
			t.Error("scope change should be detected")
		}
	})

	t.Run("secret data changed", func(t *testing.T) {
		modified := base
		modified.SecretData = testMap(map[string]string{"key": "new-value"})
		if !inputsChanged(modified, base) {
			t.Error("secret data change should be detected")
		}
	})

	t.Run("labels changed from null to set", func(t *testing.T) {
		modified := base
		modified.Labels = testMap(map[string]string{"app": "test"})
		if !inputsChanged(modified, base) {
			t.Error("labels change should be detected")
		}
	})

	t.Run("annotations changed from null to set", func(t *testing.T) {
		modified := base
		modified.Annotations = testMap(map[string]string{"note": "test"})
		if !inputsChanged(modified, base) {
			t.Error("annotations change should be detected")
		}
	})

	t.Run("computed fields ignored", func(t *testing.T) {
		plan := base
		plan.ID = types.StringValue("default/test")
		plan.InputHash = types.StringValue("abc123")
		plan.SealedSecretJSON = types.StringValue("{}")
		plan.SealedSecretYAML = types.StringValue("---")
		plan.EncryptedData = testMap(map[string]string{"key": "encrypted"})

		state := base
		state.ID = types.StringValue("default/test")
		state.InputHash = types.StringValue("different")
		state.SealedSecretJSON = types.StringValue("{different}")
		state.SealedSecretYAML = types.StringValue("different")
		state.EncryptedData = testMap(map[string]string{"key": "other-encrypted"})

		if inputsChanged(plan, state) {
			t.Error("changes to computed fields should not trigger re-encryption")
		}
	})
}
