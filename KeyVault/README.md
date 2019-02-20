# Setup KeyVault
A keyvault needs to be set up t store the letsencrypt challenge and the SSL-certificate. Follow the steps below to setup a KeyVault

### Create resource group
```
az group create --name myResourceGroup --location westeurope
```

### Create keyvault
```
az keyvault create --name letsencryptvault --resource-group myResourceGroup
```

The name is important to remember when creating your Azure Functions, since we need to give the Azure Functions permissions to write and read from the newly created KeyVault. With the above example, your KeyVault will be located at `https://letsencryptvault.vault.azure.net`

