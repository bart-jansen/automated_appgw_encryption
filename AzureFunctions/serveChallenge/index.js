
const KeyVault = require('azure-keyvault');
const msRestAzure = require('ms-rest-azure');

module.exports = function (context, req) {
    if(context && context.bindingData && context.bindingData.code && process.env.KEYVAULT_NAME) {
        const secretName = context.bindingData.code;

        context.log(`Checking for ACME challenge response at '${secretName}'...`);

        msRestAzure.loginWithAppServiceMSI({resource: 'https://vault.azure.net'}).then(credentials => {
            const keyVaultClient = new KeyVault.KeyVaultClient(credentials);
            const vaultUri = `https://${process.env.KEYVAULT_NAME}.vault.azure.net/`;
            
            keyVaultClient.getSecret(vaultUri, secretName, "").then(secretData => {
                context.log(`ACME challenge response file '${secretName}' read successfully.`);
                context.log(secretData.value);

                context.res = {
                    status: 200,
                    headers: { "Content-Type": "text/plain" },
                    body: secretData.value
                };

                context.done();
            }).catch(err => {
                context.log.error(err);

                context.res = {
                    status: 404,
                    headers: { "Content-Type": "text/plain" },
                    body: 'Error getting secret'
                };
        
                context.done();
            });

        }).catch(err => {
            context.log.error(err);

            context.res = {
                status: 404,
                headers: { "Content-Type": "text/plain" },
                body: 'Error logging in with MSI'
            };
    
            context.done();
        })
    }
    else {
        context.log('No challenge code supplied or keyvault not set up in env variables');
        context.res = {
            status: 404,
            headers: { "Content-Type": "text/plain" },
            body: 'No challenge code supplied or keyvault not set up in env variables'
        };

        context.done();
    }
};