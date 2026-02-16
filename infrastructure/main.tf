# =============================================================================
# IAMGuardian — Configuration Terraform principale
# =============================================================================
#
# Ce fichier configure les providers Terraform pour les 3 clouds.
# Pour l'instant c'est un squelette — sera complété en Phase 9.
#
# Utilisation :
#   cd infrastructure
#   terraform init
#   terraform plan
#   terraform apply
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    # Provider AWS — pour Lambda, EventBridge, IAM, Secrets Manager
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    # Provider Google Cloud — pour Firestore, Cloud Run, Gemini API
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }

    # Provider Azure — pour lecture Entra ID et RBAC
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# --- Providers ---
# TODO Phase 9 : Configurer les providers avec les bonnes régions et credentials

# provider "aws" {
#   region = var.aws_region
# }

# provider "google" {
#   project = var.gcp_project_id
#   region  = var.gcp_region
# }

# provider "azurerm" {
#   features {}
#   subscription_id = var.azure_subscription_id
# }
