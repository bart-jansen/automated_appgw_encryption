'use strict';

const msRestAzure = require('ms-rest-azure');
const NetworkManagementClient = require('azure-arm-network');

module.exports = class AppGwFqdn {
    constructor (options) {
        this.subscriptionId = options.subscriptionId || (process.env.WEBSITE_OWNER_NAME ? process.env.WEBSITE_OWNER_NAME.split('+')[0] : '');
        this.rgName = options.rgName;
        this.appgwName = options.appgwName;
    }

    getMSICredentials () {
        return msRestAzure.loginWithAppServiceMSI({resource: 'https://management.azure.com'});
        // return msRestAzure.interactiveLogin({resource: 'https://management.azure.com'});
    }


    readAppGW () {
        return this.networkClient.applicationGateways.get(this.rgName, this.appgwName);
    }

    getIp (publicIpName) {
        return this.networkClient.publicIPAddresses.get(this.rgName, publicIpName);
    }


    getFqdn (callback) {
        this.getMSICredentials().then(credentials => {
            this.networkClient = new NetworkManagementClient(credentials, this.subscriptionId);

            this.readAppGW().then(appGwRes => {
                let ipId = appGwRes.frontendIPConfigurations[0].publicIPAddress.id.split('/');
                let publicIpName = ipId[ipId.length-1];

                this.getIp(publicIpName).then(ipRes => {

                    callback(null, ipRes.dnsSettings.fqdn);
                }).catch(err => {
                    callback('error reading from ip, ' + err);
                });
                
            }).catch(err => {
                callback('error reading from appgw, ' + err);
            });
        });
    }
}