package sealed_secret

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	ktypes "github.com/phaezer/terraform-provider-kubeseal/internal/types"
)

var _ resource.Resource = &SealedSecretResource{}
var _ resource.ResourceWithConfigure = &SealedSecretResource{}

type SealedSecretResource struct {
	providerData *ktypes.KubesealProviderData
}

type SealedSecretResourceModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Namespace        types.String `tfsdk:"namespace"`
	Type             types.String `tfsdk:"type"`
	Scope            types.String `tfsdk:"scope"`
	SecretData       types.Map    `tfsdk:"secret_data"`
	Labels           types.Map    `tfsdk:"labels"`
	Annotations      types.Map    `tfsdk:"annotations"`
	EncryptedData    types.Map    `tfsdk:"encrypted_data"`
	SealedSecretJSON types.String `tfsdk:"sealed_secret_json"`
	SealedSecretYAML types.String `tfsdk:"sealed_secret_yaml"`
	InputHash        types.String `tfsdk:"input_hash"`
}

func NewSealedSecretResource() resource.Resource {
	return &SealedSecretResource{}
}

func (r *SealedSecretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sealed_secret"
}

func (r *SealedSecretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Encrypts Kubernetes secret data into a SealedSecret manifest using the sealed-secrets controller certificate.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier in the format namespace/name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the secret.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"namespace": schema.StringAttribute{
				Required:    true,
				Description: "Namespace of the secret.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("Opaque"),
				Description: "Kubernetes secret type (e.g., Opaque, kubernetes.io/tls).",
			},
			"scope": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("strict"),
				Description: "Sealing scope: strict, namespace-wide, or cluster-wide.",
				Validators: []validator.String{
					stringvalidator.OneOf("strict", "namespace-wide", "cluster-wide"),
				},
			},
			"secret_data": schema.MapAttribute{
				Required:    true,
				Sensitive:   true,
				ElementType: types.StringType,
				Description: "Map of secret key-value pairs to encrypt.",
			},
			"labels": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Labels to apply to the SealedSecret template metadata.",
			},
			"annotations": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Annotations to apply to the SealedSecret template metadata.",
			},
			"encrypted_data": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Map of encrypted key-value pairs (base64-encoded ciphertext).",
				PlanModifiers: []planmodifier.Map{
					&reencryptMapIfChanged{},
				},
			},
			"sealed_secret_json": schema.StringAttribute{
				Computed:    true,
				Description: "The full SealedSecret manifest as JSON.",
				PlanModifiers: []planmodifier.String{
					&reencryptStringIfChanged{},
				},
			},
			"sealed_secret_yaml": schema.StringAttribute{
				Computed:    true,
				Description: "The full SealedSecret manifest as YAML.",
				PlanModifiers: []planmodifier.String{
					&reencryptStringIfChanged{},
				},
			},
			"input_hash": schema.StringAttribute{
				Computed:    true,
				Description: "SHA-256 hash of the inputs, used internally for plan stability.",
			},
		},
	}
}

func (r *SealedSecretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	data, ok := req.ProviderData.(*ktypes.KubesealProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *types.KubesealProviderData, got: %T", req.ProviderData),
		)
		return
	}
	r.providerData = data
}

func (r *SealedSecretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan SealedSecretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.encryptAndSetState(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SealedSecretResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
	// Local-only encryption resource — state is preserved as-is.
}

func (r *SealedSecretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan SealedSecretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.encryptAndSetState(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SealedSecretResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No-op: local-only resource with no remote state to destroy.
}

func (r *SealedSecretResource) encryptAndSetState(ctx context.Context, model *SealedSecretResourceModel, diagnostics *diag.Diagnostics) {
	name := model.Name.ValueString()
	namespace := model.Namespace.ValueString()
	secretType := model.Type.ValueString()
	scope := parseScopeString(model.Scope.ValueString())

	secretDataMap := make(map[string]string)
	diagnostics.Append(model.SecretData.ElementsAs(ctx, &secretDataMap, false)...)

	var labelsMap map[string]string
	if !model.Labels.IsNull() && !model.Labels.IsUnknown() {
		labelsMap = make(map[string]string)
		diagnostics.Append(model.Labels.ElementsAs(ctx, &labelsMap, false)...)
	}

	var annotationsMap map[string]string
	if !model.Annotations.IsNull() && !model.Annotations.IsUnknown() {
		annotationsMap = make(map[string]string)
		diagnostics.Append(model.Annotations.ElementsAs(ctx, &annotationsMap, false)...)
	}

	pubKey, err := fetchCertificate(ctx, r.providerData.RestConfig, r.providerData.ControllerNamespace, r.providerData.ControllerName)
	if err != nil {
		diagnostics.AddError("Failed to fetch sealing certificate", err.Error())
		return
	}

	ss, err := sealSecret(name, namespace, secretType, scope, secretDataMap, labelsMap, annotationsMap, pubKey)
	if err != nil {
		diagnostics.AddError("Failed to seal secret", err.Error())
		return
	}

	jsonOut, err := sealedSecretToJSON(ss)
	if err != nil {
		diagnostics.AddError("Failed to serialize SealedSecret to JSON", err.Error())
		return
	}

	yamlOut, err := sealedSecretToYAML(ss)
	if err != nil {
		diagnostics.AddError("Failed to serialize SealedSecret to YAML", err.Error())
		return
	}

	hash := secretDataHash(secretDataMap)

	model.ID = types.StringValue(fmt.Sprintf("%s/%s", namespace, name))
	encMap, mapDiags := types.MapValueFrom(ctx, types.StringType, ss.Spec.EncryptedData)
	diagnostics.Append(mapDiags...)
	model.EncryptedData = encMap
	model.SealedSecretJSON = types.StringValue(jsonOut)
	model.SealedSecretYAML = types.StringValue(yamlOut)
	model.InputHash = types.StringValue(hash)
}
