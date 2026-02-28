package types

import "k8s.io/client-go/rest"

// KubesealProviderData holds the configured Kubernetes client and controller
// settings, shared between data sources and resources.
type KubesealProviderData struct {
	RestConfig          *rest.Config
	ControllerName      string
	ControllerNamespace string
}
