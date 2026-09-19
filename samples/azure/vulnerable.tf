# SentinelGuard AI sample — VULNERABLE Azure Terraform (never applied).
# Expected: 4 findings -> AZ-NSG-001 x2, AZ-STOR-001 x2

resource "azurerm_storage_account" "public" {
  name                            = "acmepublicstore"
  resource_group_name             = "rg-demo"
  location                        = "westeurope"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
}

resource "azurerm_storage_container" "open" {
  name                  = "assets"
  storage_account_name  = azurerm_storage_account.public.name
  container_access_type = "blob"
}

resource "azurerm_network_security_group" "web" {
  name                = "web-nsg"
  location            = "westeurope"
  resource_group_name = "rg-demo"

  security_rule {
    name                       = "allow-ssh-any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
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
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_rule" "rdp" {
  name                        = "allow-rdp-internet"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_ranges     = ["3389", "8080"]
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-demo"
  network_security_group_name = azurerm_network_security_group.web.name
}
