data "kubeseal_certificate" "main" {}

output "certificate" {
  value = data.kubeseal_certificate.main.certificate
}
