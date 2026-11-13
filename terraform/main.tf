terraform {
  required_version = ">= 1.5"
  required_providers {
    azuread = { source = "hashicorp/azuread", version = "~> 3.0" }
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
  }
}

variable "subscription_id" { type = string }
variable "break_glass_group_id" { type = string }

# Role ids: Global Administrator, Privileged Role Administrator, Security Administrator.
locals {
  admin_roles = [
    "62e90394-69f5-4237-9190-012177145e10",
    "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "194ae4cb-b126-40b2-bd5b-6091b380977d",
  ]
}

resource "azuread_conditional_access_policy" "admin_mfa" {
  display_name = "Require MFA for privileged roles"
  state        = "enabledForReportingButNotEnforced"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_roles  = local.admin_roles
      excluded_groups = [var.break_glass_group_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

resource "azuread_conditional_access_policy" "block_legacy" {
  display_name = "Block legacy authentication"
  state        = "enabledForReportingButNotEnforced"

  conditions {
    client_app_types = ["exchangeActiveSync", "other"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = [var.break_glass_group_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# Azure RBAC: a group gets read access at subscription scope. People join the group through an access review.
resource "azuread_group" "readers" {
  display_name     = "azure-subscription-readers"
  security_enabled = true
}

resource "azurerm_role_assignment" "readers" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Reader"
  principal_id         = azuread_group.readers.object_id
}
