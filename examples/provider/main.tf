terraform {
  required_providers {
    kubeseal = {
      source = "registry.terraform.io/phaezer/kubeseal"
    }
  }
}

# Uses default kubeconfig at ~/.kube/config
provider "kubeseal" {
  controller_name      = "sealed-secrets-controller"
  controller_namespace = "kube-system"
}
