# Setup Application Gateway
Follow the instructions below to setup an Application Gateway in Azure with an NGINX-based virtual machine scale set, more detailed information can be found [here](https://docs.microsoft.com/en-us/azure/application-gateway/tutorial-create-vmss-cli).

## Deploy resources
### Create resource group
```
az group create --name myResourceGroup --location westeurope
```

### Create network resources 
```
az network vnet create \
  --name myVNet \
  --resource-group myResourceGroup \
  --location westeurope \
  --address-prefix 10.0.0.0/16 \
  --subnet-name myAGSubnet \
  --subnet-prefix 10.0.1.0/24
az network vnet subnet create \
  --name myBackendSubnet \
  --resource-group myResourceGroup \
  --vnet-name myVNet \
  --address-prefix 10.0.2.0/24
```

### Create public IP with DNS label
Change **mydnslabel** to your unique FQDN (e.g. mydnslabel becomes mydnslabel.westeurope.cloudapp.azure.com) that you want to generate an automated SSL certificate for. Note that this dnslabel needs to be unique.
```
az network public-ip create -g myResourceGroup -n myAGPublicIPAddress --dns-name mydnslabel
```

### Create application gateway
```
az network application-gateway create \
  --name myAppGateway \
  --location westeurope \
  --resource-group myResourceGroup \
  --vnet-name myVNet \
  --subnet myAGsubnet \
  --capacity 2 \
  --sku Standard_Medium \
  --http-settings-cookie-based-affinity Disabled \
  --frontend-port 80 \
  --http-settings-port 80 \
  --http-settings-protocol Http \
  --public-ip-address myAGPublicIPAddress
```

### Create virtual machine scale set
```
az vmss create \
  --name myvmss \
  --resource-group myResourceGroup \
  --image UbuntuLTS \
  --admin-username azureuser \
  --admin-password Azure123456! \
  --instance-count 2 \
  --vnet-name myVNet \
  --subnet myBackendSubnet \
  --vm-sku Standard_DS2 \
  --upgrade-policy-mode Automatic \
  --app-gateway myAppGateway \
  --backend-pool-name appGatewayBackendPool
```

### Install NGINX on VMSS
```
az vmss extension set \
  --publisher Microsoft.Azure.Extensions \
  --version 2.0 \
  --name CustomScript \
  --resource-group myResourceGroup \
  --vmss-name myvmss \
  --settings '{ "fileUris": ["https://raw.githubusercontent.com/Azure/azure-docs-powershell-samples/master/application-gateway/iis/install_nginx.sh"], "commandToExecute": "./install_nginx.sh" }'
```

### Test application gateway
Once everything is deployed, we can test if the (non-SSL enabled) application gateway works by pointing the browser to your newly created public ip.

To show the FQDN of your public IP:
```
az network public-ip show \
  --resource-group myResourceGroup \
  --name myAGPublicIPAddress \
  --query [ipAddress] \
  --output tsv
```

Now point your browser to the IP (e.g. mydnslabel.westeurope.cloudapp.azure.com) and it will should show the result below alternating between the different VMs in the scale set when refreshing
![](../img/app-gw-browser.png)

## Configure letsencrypt routing
To setup routing to complete the letsencrypt challenge, path-based application gateway routing needs to be setup by modifying the existing rule for the port 80 HTTPListener.

### Create redirect-config
Change the target-url to the URL of your Azure Function
```
az network application-gateway redirect-config create \
  --resource-group myResourceGroup \
  --gateway-name myAppGateway \
  --name letsencryptRedirect \
  --type Permanent \
  --include-query-string true \
  --target-url https://acmefunction.azurewebsites.net/api/requestCertificate/
```

### Create URL path map
```
az network application-gateway url-path-map create \
  --gateway-name myAppGateway \
  --name httpPath \
  --paths /.well-known/acme-challenge/* \
  --resource-group myResourceGroup \
  --rule-name letsencrypt \
  --redirect-config letsencryptRedirect
```

### Update existing rule
```
az network application-gateway rule update \
  --gateway-name myAppGateway \
  --name rule1 \
  --resource-group myResourceGroup \
  --rule-type PathBasedRouting \
  --url-path-map httpPath
```

## Setup port 443 (HTTPS) 


### Create self signed SSL certificate

Before we apply the actual certificate, we configure application gateway with a self signed certificate which we can then later easily replace with a valid SSL certificate issued by letsencrypt. Below steps are using OpenSSL, if you're unable to use/install this you can also create a certificate using [cert-depot](https://www.cert-depot.com/).
- Generate private key: `openssl genrsa 2048 > private.pem`
- Generate self signed certificate: `openssl req -x509 -new -key private.pem -out public.pem`
- Convert certificate to PFX format: `openssl pkcs12 -export -in public.pem -inkey private.pem -out mycert.pfx -passout pass:MySecretP@ss`

For your password you can pick anything, please do make sure to memorize your chosen password as we need this in the next steps

### Upload SSL certificate
```
az network application-gateway ssl-cert create \
  --resource-group myResourceGroup \
  --gateway-name myAppGateway \
  --name appgw-cert \
  --cert-file mycert.pfx \
  --cert-password MySecretP@ss
```

### Create new frontend HTTPs port to listen to port 443
```
az network application-gateway frontend-port create \
  --port 443 \
  --gateway-name myAppGateway \
  --resource-group myResourceGroup \
  --name httpsPort
```

### Create httpListener for port 443 with certificate
```
az network application-gateway http-listener create \
  --gateway-name myAppGateway \
  --resource-group myResourceGroup \
  --frontend-port httpsPort \
  --name httpsListener \
  --ssl-cert appgw-cert
```

### Create redirect-config for HTTP to HTTPS redirection
```
az network application-gateway redirect-config create \
  --resource-group myResourceGroup \
  --gateway-name myAppGateway \
  --name httpToHttpsRedirect \
  --type Permanent \
  --include-query-string true \
  --target-listener httpsListener
```

### Add URL path for HTTP to HTTPS redirection
```
az network application-gateway url-path-map rule create \
  --gateway-name myAppGateway \
  --name httpToHttps \
  --path-map-name httpPath \
  --paths /* \
  --resource-group myResourceGroup \
  --redirect-config httpToHttpsRedirect
```

Once the Azure Function requests and applies the working SSL certificate issued by letsencrypt, the Azure Functions automatically replaces the self signed certificate issued in these instructions.