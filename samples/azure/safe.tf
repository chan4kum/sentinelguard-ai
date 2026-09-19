# SentinelGuard AI sample — SAFE Azure Terraform. Expected: 0 findings.

resource "azurerm_storage_account" "private" {
  name                            = "acmeprivatestore"
  resource_group_name             = "rg-demo"
  location                        = "westeurope"
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "private" {
  name                  = "data"
  storage_account_name  = azurerm_storage_account.private.name
  container_access_type = "private"
}

resource "azurerm_network_security_group" "web" {
  name                = "web-nsg"
  location            = "westeurope"
  resource_group_name = "rg-demo"

  security_rule {
    name                       = "allow-ssh-from-corp"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.0.0/8"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-https"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "deny-ssh-internet"
    priority                   = 300
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
