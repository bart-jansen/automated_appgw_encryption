'use strict';

const msRestAzure = require('ms-rest-azure');
const NetworkManagementClient = require('azure-arm-network');
const fs = require('fs');

module.exports = class ApplyCertificate {
    constructor (options) {
        this.subscriptionId = options.subscriptionId || (process.env.WEBSITE_OWNER_NAME ? process.env.WEBSITE_OWNER_NAME.split('+')[0] : '');
        this.rgName = options.rgName;
        this.appgwName = options.appgwName;
        this.certPath = options.certPath;
        this.certPwd = options.certPwd;
        this.certName = options.certName || 'appgw-cert';
    }

    base64Encode (file) {
        // read binary data
        var bitmap = fs.readFileSync(file);
        // convert binary data to base64 encoded string
        return new Buffer(bitmap).toString('base64');
    }

    getMSICredentials () {
        return msRestAzure.loginWithAppServiceMSI({resource: 'https://management.azure.com'});
        // return msRestAzure.interactiveLogin({resource: 'https://management.azure.com'});
    }

    applyCertData (data) {
        data.sslCertificates = [{
            name: this.certName,
            data: this.base64Encode(this.certPath),
            password: this.certPwd,
        }];

        return data;
    }

    readAppGW () {
        return this.networkClient.applicationGateways.get(this.rgName, this.appgwName);
    }

    updateAppGW (data) {
        return this.networkClient.applicationGateways.createOrUpdate(this.rgName, this.appgwName, data);
    }

    applyCertFlow (callback) {
        this.getMSICredentials().then(credentials => {
            this.networkClient = new NetworkManagementClient(credentials, this.subscriptionId);

            this.readAppGW().then(res => {
                let newData = this.applyCertData(res);

                this.updateAppGW(newData).then(updateRes => {
                    // console.log('successfully updated appgw');
                    callback(null);
                }).catch(err => {
                    callback('error updating appgw, ' + err);
                });
            }).catch(err => {
                callback('error reading from appgw, ' + err);
            });
        });
    }
}