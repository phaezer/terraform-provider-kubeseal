# Terraform Provider for Kubeseal (bitnami-labs/sealed-secrets)

> [!WARNING]
> This project is currently a work in progress and should not be considered stable

_This provider is built on the [Terraform Plugin Framework](https://github.com/hashicorp/terraform-plugin-framework)._

A [Terraform](https://www.terraform.io) provider for encrypting Kubernetes secrets into [SealedSecrets](https://github.com/bitnami-labs/sealed-secrets) using the sealed-secrets controller certificate. This allows you to safely store encrypted secret manifests in version control and apply them to your cluster.

This provider exposes:

- A resource (`kubeseal_sealed_secret`) that encrypts secret key-value pairs and outputs a ready-to-apply SealedSecret manifest in JSON and YAML.
- A data source (`kubeseal_certificate`) that fetches the public sealing certificate from the sealed-secrets controller.

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.24
- A running [sealed-secrets controller](https://github.com/bitnami-labs/sealed-secrets) in your Kubernetes cluster

## Building The Provider

1. Clone the repository
1. Enter the repository directory
1. Build the provider using the Go `install` command:

```shell
go install
```

## Using the Provider

### Provider Configuration

```hcl
terraform {
  required_providers {
    kubeseal = {
      source  = "registry.terraform.io/phaezer/kubeseal"
      version = "~> 0.1"
    }
  }
}

# Uses default kubeconfig at ~/.kube/config
provider "kubeseal" {
  controller_name      = "sealed-secrets-controller"
  controller_namespace = "kube-system"
}
```

The provider also supports explicit Kubernetes API server credentials:

```hcl
provider "kubeseal" {
  kubernetes {
    host                   = "https://my-cluster.example.com"
    token                  = "my-bearer-token"
    cluster_ca_certificate = file("ca.crt")
  }
}
```

### Encrypting a Secret

```hcl
resource "kubeseal_sealed_secret" "example" {
  name      = "my-secret"
  namespace = "default"
  type      = "Opaque"
  scope     = "strict"

  secret_data = {
    username = "admin"
    password = "supersecret"
  }

  labels = {
    app = "my-app"
  }
}

output "sealed_secret_yaml" {
  value = kubeseal_sealed_secret.example.sealed_secret_yaml
}

output "sealed_secret_json" {
  value = kubeseal_sealed_secret.example.sealed_secret_json
}
```

The `sealed_secret_yaml` and `sealed_secret_json` outputs contain the full SealedSecret manifest, ready to be committed to version control or applied directly to your cluster with `kubectl apply`.

### Fetching the Sealing Certificate

```hcl
data "kubeseal_certificate" "main" {}

output "certificate" {
  value = data.kubeseal_certificate.main.certificate
}
```
