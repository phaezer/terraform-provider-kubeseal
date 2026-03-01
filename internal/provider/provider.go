package provider

import (
	"context"
	"os"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/phaezer/terraform-provider-kubeseal/internal/datasources/certificate"
	"github.com/phaezer/terraform-provider-kubeseal/internal/resources/sealed_secret"
	ktypes "github.com/phaezer/terraform-provider-kubeseal/internal/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var _ provider.Provider = &KubesealProvider{}

type KubesealProvider struct {
	version string
}

type KubesealProviderModel struct {
	Kubernetes          *KubernetesModel `tfsdk:"kubernetes"`
	ControllerName      types.String     `tfsdk:"controller_name"`
	ControllerNamespace types.String     `tfsdk:"controller_namespace"`
}

type KubernetesModel struct {
	ConfigPath           types.String `tfsdk:"config_path"`
	ConfigContext        types.String `tfsdk:"config_context"`
	Host                 types.String `tfsdk:"host"`
	Token                types.String `tfsdk:"token"`
	ClientCertificate    types.String `tfsdk:"client_certificate"`
	ClientKey            types.String `tfsdk:"client_key"`
	ClusterCACertificate types.String `tfsdk:"cluster_ca_certificate"`
	Insecure             types.Bool   `tfsdk:"insecure"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &KubesealProvider{
			version: version,
		}
	}
}

func (p *KubesealProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "kubeseal"
	resp.Version = p.version
}

func (p *KubesealProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The kubeseal provider encrypts Kubernetes secrets into SealedSecrets using the sealed-secrets controller certificate.",
		Attributes: map[string]schema.Attribute{
			"controller_name": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the sealed-secrets controller service. Defaults to \"sealed-secrets-controller\".",
			},
			"controller_namespace": schema.StringAttribute{
				Optional:    true,
				Description: "Namespace of the sealed-secrets controller. Defaults to \"kube-system\".",
			},
		},
		Blocks: map[string]schema.Block{
			"kubernetes": schema.SingleNestedBlock{
				Description: "Kubernetes connection configuration.",
				Attributes: map[string]schema.Attribute{
					"config_path": schema.StringAttribute{
						Optional:    true,
						Description: "Path to the kubeconfig file. Defaults to ~/.kube/config.",
					},
					"config_context": schema.StringAttribute{
						Optional:    true,
						Description: "Context to use in the kubeconfig.",
					},
					"host": schema.StringAttribute{
						Optional:    true,
						Description: "Kubernetes API server URL. When set, explicit authentication fields are used instead of kubeconfig.",
					},
					"token": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "Bearer token for authentication.",
					},
					"client_certificate": schema.StringAttribute{
						Optional:    true,
						Description: "PEM-encoded client certificate for TLS authentication.",
					},
					"client_key": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "PEM-encoded client private key for TLS authentication.",
					},
					"cluster_ca_certificate": schema.StringAttribute{
						Optional:    true,
						Description: "PEM-encoded cluster CA certificate.",
					},
					"insecure": schema.BoolAttribute{
						Optional:    true,
						Description: "Skip TLS verification.",
					},
				},
			},
		},
	}
}

func (p *KubesealProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config KubesealProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	restConfig, err := buildRestConfig(config.Kubernetes)
	if err != nil {
		resp.Diagnostics.AddError("Failed to build Kubernetes configuration", err.Error())
		return
	}

	controllerName := "sealed-secrets-controller"
	if !config.ControllerName.IsNull() && !config.ControllerName.IsUnknown() {
		controllerName = config.ControllerName.ValueString()
	}

	controllerNamespace := "kube-system"
	if !config.ControllerNamespace.IsNull() && !config.ControllerNamespace.IsUnknown() {
		controllerNamespace = config.ControllerNamespace.ValueString()
	}

	providerData := &ktypes.KubesealProviderData{
		RestConfig:          restConfig,
		ControllerName:      controllerName,
		ControllerNamespace: controllerNamespace,
	}

	resp.DataSourceData = providerData
	resp.ResourceData = providerData
}

func (p *KubesealProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		sealed_secret.NewSealedSecretResource,
	}
}

func (p *KubesealProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		certificate.NewCertificateDataSource,
	}
}

func buildRestConfig(k8s *KubernetesModel) (*rest.Config, error) {
	if k8s != nil && !k8s.Host.IsNull() && k8s.Host.ValueString() != "" {
		tlsConfig := rest.TLSClientConfig{
			Insecure: k8s.Insecure.ValueBool(),
		}
		if !k8s.ClientCertificate.IsNull() {
			tlsConfig.CertData = []byte(k8s.ClientCertificate.ValueString())
		}
		if !k8s.ClientKey.IsNull() {
			tlsConfig.KeyData = []byte(k8s.ClientKey.ValueString())
		}
		if !k8s.ClusterCACertificate.IsNull() {
			tlsConfig.CAData = []byte(k8s.ClusterCACertificate.ValueString())
		}

		return &rest.Config{
			Host:            k8s.Host.ValueString(),
			BearerToken:     k8s.Token.ValueString(),
			TLSClientConfig: tlsConfig,
		}, nil
	}

	configPath := ""
	if k8s != nil && !k8s.ConfigPath.IsNull() {
		configPath = k8s.ConfigPath.ValueString()
	}
	if configPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			configPath = filepath.Join(home, ".kube", "config")
		}
	}

	configContext := ""
	if k8s != nil && !k8s.ConfigContext.IsNull() {
		configContext = k8s.ConfigContext.ValueString()
	}

	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: configPath}
	overrides := &clientcmd.ConfigOverrides{}
	if configContext != "" {
		overrides.CurrentContext = configContext
	}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	return kubeConfig.ClientConfig()
}
