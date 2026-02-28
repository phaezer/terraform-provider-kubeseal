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
