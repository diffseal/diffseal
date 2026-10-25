terraform {
  backend "s3" {
    bucket = "acme-terraform-state"
    key    = "orders/terraform.tfstate"
    region = "eu-north-1"
  }
}

provider "aws" {
  region = "eu-north-1"
}

module "orders" {
  source      = "../../../modules/orders-service"
  environment = "prod"
}
