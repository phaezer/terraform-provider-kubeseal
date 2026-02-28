package sealed_secret

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// reencryptStringIfChanged preserves the state value for computed string attributes
// when no input attributes have changed, preventing unnecessary re-encryption diffs.
type reencryptStringIfChanged struct{}

func (m *reencryptStringIfChanged) Description(_ context.Context) string {
	return "Preserves the existing value when inputs have not changed."
}

func (m *reencryptStringIfChanged) MarkdownDescription(_ context.Context) string {
	return "Preserves the existing value when inputs have not changed."
}

func (m *reencryptStringIfChanged) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If there's no state (create), let it be unknown
	if req.StateValue.IsNull() {
		return
	}

	// Check if any input attributes changed by comparing plan vs state input_hash
	var planModel, stateModel SealedSecretResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &planModel)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &stateModel)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if inputsChanged(planModel, stateModel) {
		// Inputs changed — mark as unknown so it gets recomputed during apply
		resp.PlanValue = types.StringUnknown()
		return
	}

	// No changes — preserve the existing state value
	resp.PlanValue = req.StateValue
}

// reencryptMapIfChanged preserves the state value for computed map attributes
// when no input attributes have changed.
type reencryptMapIfChanged struct{}

func (m *reencryptMapIfChanged) Description(_ context.Context) string {
	return "Preserves the existing value when inputs have not changed."
}

func (m *reencryptMapIfChanged) MarkdownDescription(_ context.Context) string {
	return "Preserves the existing value when inputs have not changed."
}

func (m *reencryptMapIfChanged) PlanModifyMap(ctx context.Context, req planmodifier.MapRequest, resp *planmodifier.MapResponse) {
	// If there's no state (create), let it be unknown
	if req.StateValue.IsNull() {
		return
	}

	var planModel, stateModel SealedSecretResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &planModel)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &stateModel)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if inputsChanged(planModel, stateModel) {
		resp.PlanValue = types.MapUnknown(types.StringType)
		return
	}

	resp.PlanValue = req.StateValue
}

// inputsChanged compares the plan and state models to determine if any input
// attributes that affect encryption have changed.
func inputsChanged(plan, state SealedSecretResourceModel) bool {
	if !plan.SecretData.Equal(state.SecretData) {
		return true
	}
	if !plan.Scope.Equal(state.Scope) {
		return true
	}
	if !plan.Type.Equal(state.Type) {
		return true
	}
	if !plan.Labels.Equal(state.Labels) {
		return true
	}
	if !plan.Annotations.Equal(state.Annotations) {
		return true
	}
	if !plan.Name.Equal(state.Name) {
		return true
	}
	if !plan.Namespace.Equal(state.Namespace) {
		return true
	}
	return false
}
