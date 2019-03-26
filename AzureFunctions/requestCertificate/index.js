'use strict';

let Acme2 = require('./Acme2'),
    ApplyCertificate = require('./ApplyCertificate'),
    AppGwFqdn = require('./AppGwFqdn');

module.exports = function (context, req) {
    if ('KEYVAULT_NAME','EMAIL_CERT','APPGW_NAME','APPGW_RG' in process.env) {
        let appgwFqdn = new AppGwFqdn({
            rgName: process.env.APPGW_RG,
            appgwName: process.env.APPGW_NAME
        });

        appgwFqdn.getFqdn(function(err, fqdn) {
            if(err) {
                context.log('error with getting fqdn');
                context.log(err);
                context.done();
            }
            else {
                context.log('got fqdn');
                context.log(fqdn);

                let acme = new Acme2({
                    context: context,
                    email: process.env.EMAIL_CERT,
                    keyVaultName: process.env.KEYVAULT_NAME,
                    prod: true
                });

                acme.getCertificate(fqdn, function (err, cert, key) {
                    if(err) {
                        context.log('error with getting certificate');
                        context.log(err);
                        context.done();
                    }
                    else {
                        context.log('got cert');
                        context.log(cert);
                        context.log('got key');
                        context.log(key);

                        acme.convertCertificate(cert, key, 'appgw.pfx', function (err, pfx, randomCertPass) {
                            let deployCert = new ApplyCertificate({
                                // subscriptionId: ''
                                rgName: process.env.APPGW_RG,
                                appgwName: process.env.APPGW_NAME,
                                certPath: pfx,
                                certPwd: randomCertPass,
                                certName: 'appgw-cert'
                            });

                            deployCert.applyCertFlow(function(err) {
                                if(err) {
                                    context.log('error with applying certificate');
                                    context.log(err);
                                    context.done();
                                }
                                else {
                                    context.log('successfully deployed certificate')
                                    context.done();
                                }
                            })
                        });
                    }
                });
            }
        });
    }
    else {
        context.log('Not all environment variables are set');
        context.done();
    }
}
