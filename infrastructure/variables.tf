# =============================================================================
# IAMGuardian — Variables Terraform
# =============================================================================
# Ces variables seront utilisées lors du déploiement cloud (Phase 9+).
# =============================================================================

variable "project_name" {
  description = "Nom du projet (utilisé comme préfixe pour les ressources)"
  type        = string
  default     = "csl-dev-iamguardian"
}

variable "environment" {
  description = "Environnement de déploiement (dev ou prod)"
  type        = string
  default     = "dev"
}

# --- AWS ---

variable "aws_region" {
  description = "Région AWS pour les ressources"
  type        = string
  default     = "eu-west-1"
}

# --- GCP ---

variable "gcp_project_id" {
  description = "ID du projet Google Cloud"
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "Région GCP pour les ressources"
  type        = string
  default     = "europe-west1"
}

# --- Azure ---

variable "azure_subscription_id" {
  description = "ID de la souscription Azure"
  type        = string
  default     = ""
}
