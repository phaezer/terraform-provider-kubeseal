package certificate

import (
	"context"
	"fmt"
	"io"

	ktypes "github.com/phaezer/terraform-provider-kubeseal/internal/types"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

var _ datasource.DataSource = &CertificateDataSource{}
var _ datasource.DataSourceWithConfigure = &CertificateDataSource{}

type CertificateDataSource struct {
	providerData *ktypes.KubesealProviderData
}

type CertificateDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Certificate types.String `tfsdk:"certificate"`
}

func NewCertificateDataSource() datasource.DataSource {
	return &CertificateDataSource{}
}

func (d *CertificateDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (d *CertificateDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches the sealing certificate from the sealed-secrets controller.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier in the format namespace/name.",
			},
			"certificate": schema.StringAttribute{
				Computed:    true,
				Description: "PEM-encoded sealing certificate from the controller.",
			},
		},
	}
}

func (d *CertificateDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	data, ok := req.ProviderData.(*ktypes.KubesealProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *types.KubesealProviderData, got: %T", req.ProviderData),
		)
		return
	}
	d.providerData = data
}

func (d *CertificateDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	restConfig := d.providerData.RestConfig
	ns := d.providerData.ControllerNamespace
	name := d.providerData.ControllerName

	restConfig.AcceptContentTypes = "application/x-pem-file, */*"
	client, err := corev1client.NewForConfig(restConfig)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create Kubernetes client", err.Error())
		return
	}

	svc, err := client.Services(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to get sealed-secrets controller service",
			fmt.Sprintf("Could not find service %s/%s: %v", ns, name, err),
		)
		return
	}

	if len(svc.Spec.Ports) == 0 {
		resp.Diagnostics.AddError("Service has no ports", fmt.Sprintf("Service %s/%s has no ports defined", ns, name))
		return
	}
	portName := svc.Spec.Ports[0].Name

	certStream, err := client.Services(ns).ProxyGet("http", name, portName, "/v1/cert.pem", nil).Stream(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Failed to fetch certificate", fmt.Sprintf("Could not fetch certificate from controller: %v", err))
		return
	}
	defer certStream.Close()

	certBytes, err := io.ReadAll(certStream)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read certificate", err.Error())
		return
	}

	state := CertificateDataSourceModel{
		ID:          types.StringValue(fmt.Sprintf("%s/%s", ns, name)),
		Certificate: types.StringValue(string(certBytes)),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
