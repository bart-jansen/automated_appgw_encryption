# Azure Functions 
Follow the steps below to deploy and setup both Azure Functions on your Azure subscription.

## Prerequisites 
Both the [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest) and [Azure Function Core Tools](https://github.com/Azure/azure-functions-core-tools/tree/master) are required to deploy the resources and Azure Functions.

Ensure you have Azure Function Core Tools **v2** installed on your local machine. To install v2 with npm:
```
npm i -g azure-functions-core-tools --unsafe-perm true
```

## Deploy resources
First create an empty resource group
```
az group create --name myResourceGroup --location westeurope
```
Create an Azure Storage account
```
az storage account create --name myStorage --location westeurope --resource-group myResourceGroup --sku Standard_LRS
```
Create a Linux-based B1 SKU AppService plan:
```
az appservice plan create -n myPlan -g myResourceGroup  --is-linux  --sku B1
```
Create Linux & Node-based Azure Function
```
az functionapp create -n myFunc --resource-group myResourceGroup -c westeurope  --storage-account myStorage --runtime node --os-type Linux
```

## Publish code
Pull down this repository, cd into this directory and publish the Azure Functions to your newly created resource with:
```
func azure functionapp publish myFunc
```