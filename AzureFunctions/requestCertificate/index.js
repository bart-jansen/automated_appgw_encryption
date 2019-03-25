let assert = require('assert'),
    async = require('async'),
    crypto = require('crypto'),
    fs = require('fs'),
    path = require('path'),
    safe = require('safetydance'),
    superagent = require('superagent'),
    util = require('util'),
    _ = require('underscore'),
    KeyVault = require('azure-keyvault'),
    msRestAzure = require('ms-rest-azure');

let ApplyCertificate = require('./ApplyCertificate'),
    AppGwFqdn = require('./AppGwFqdn');

const paths = {
    ACME_ACCOUNT_KEY_FILE: './acme.key',
    APP_CERTS_DIR: './'
};

const CA_PROD_DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory',
    CA_STAGING_DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory';

// urlsafe base64 encoding (jose)
function urlBase64Encode(string) {
    return string.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64(str) {
    let buf = util.isBuffer(str) ? str : new Buffer(str);
    return urlBase64Encode(buf.toString('base64'));
}

function getModulus(pem) {
    assert(util.isBuffer(pem));

    let stdout = safe.child_process.execSync('openssl rsa -modulus -noout', { input: pem, encoding: 'utf8' });
    if (!stdout) return null;
    let match = stdout.match(/Modulus=([0-9a-fA-F]+)$/m);
    if (!match) return null;
    return Buffer.from(match[1], 'hex');
}


module.exports = function (context, req) {
    class Acme2 {
        constructor(options) {
            assert.strictEqual(typeof options, 'object');
            this.accountKeyPem = null; // Buffer
            this.email = options.email;
            this.keyVaultUri = `https://${options.keyVaultName}.vault.azure.net/`;
            this.keyId = null;
            this.caDirectory = options.prod ? CA_PROD_DIRECTORY_URL : CA_STAGING_DIRECTORY_URL;
            this.directory = {};
        }

        getNonce(callback) {
            superagent.get(this.directory.newNonce).timeout(30 * 1000).end(function (error, response) {
                if (error && !error.response)
                    return callback(error);
                if (response.statusCode !== 204)
                    return callback('Invalid response code when fetching nonce : ' + response.statusCode);

                return callback(null, response.headers['Replay-Nonce'.toLowerCase()]);
            });
        }

        sendSignedRequest(url, payload, callback) {
            assert.strictEqual(typeof url, 'string');
            assert.strictEqual(typeof payload, 'string');
            assert.strictEqual(typeof callback, 'function');
            assert(util.isBuffer(this.accountKeyPem));

            const that = this;
            let header = {
                url: url,
                alg: 'RS256'
            };

            // keyId is null when registering account
            if (this.keyId) {
                header.kid = this.keyId;
            }
            else {
                header.jwk = {
                    e: b64(Buffer.from([0x01, 0x00, 0x01])),
                    kty: 'RSA',
                    n: b64(getModulus(this.accountKeyPem))
                };
            }

            let payload64 = b64(payload);

            this.getNonce(function (error, nonce) {
                if (error)
                    return callback(error);

                context.log('sendSignedRequest: using nonce %s for url %s', nonce, url);

                let protected64 = b64(JSON.stringify(_.extend({}, header, { nonce: nonce })));
                let signer = crypto.createSign('RSA-SHA256');
                signer.update(protected64 + '.' + payload64, 'utf8');
                let signature64 = urlBase64Encode(signer.sign(that.accountKeyPem, 'base64'));
                let data = {
                    protected: protected64,
                    payload: payload64,
                    signature: signature64
                };

                superagent.post(url).set('Content-Type', 'application/jose+json').set('User-Agent', 'acme-cloudron').send(JSON.stringify(data)).timeout(30 * 1000).end(function (error, res) {
                    if (error && !error.response)
                        return callback(error); // network errors
                    callback(null, res);
                });
            });
        }

        updateContact(registrationUri, callback) {
            assert.strictEqual(typeof registrationUri, 'string');
            assert.strictEqual(typeof callback, 'function');

            context.log(`updateContact: registrationUri: ${registrationUri} email: ${this.email}`);

            // https://github.com/ietf-wg-acme/acme/issues/30
            const payload = {
                contact: ['mailto:' + this.email]
            };

            const that = this;
            this.sendSignedRequest(registrationUri, JSON.stringify(payload), function (error, result) {
                if (error)
                    return callback('Network error when registering user: ' + error.message);
                if (result.statusCode !== 200)
                    return callback('Failed to update contact. Expecting 200 got ' + result.statusCode);

                context.log(`updateContact: contact of user updated to ${that.email}`);
                callback();
            });
        }

        registerUser(callback) {
            assert.strictEqual(typeof callback, 'function');

            let payload = {
                termsOfServiceAgreed: true
            };

            context.log('registerUser: registering user');

            let that = this;
            this.sendSignedRequest(this.directory.newAccount, JSON.stringify(payload), function (error, result) {
                if (error)
                    return callback('Network error when registering new account: ' + error.message);
                // 200 if already exists. 201 for new accounts
                if (result.statusCode !== 200 && result.statusCode !== 201)
                    return callback('Failed to register new account. Expecting 200 or 201');
                context.log(`registerUser: user registered keyid: ${result.headers.location}`);
                that.keyId = result.headers.location;
                that.updateContact(result.headers.location, callback);
            });
        }

        getKeyAuthorization(token) {
            assert(util.isBuffer(this.accountKeyPem));

            let jwk = {
                e: b64(Buffer.from([0x01, 0x00, 0x01])),
                kty: 'RSA',
                n: b64(getModulus(this.accountKeyPem))
            };

            let shasum = crypto.createHash('sha256');
            shasum.update(JSON.stringify(jwk));
            let thumbprint = urlBase64Encode(shasum.digest('base64'));

            return token + '.' + thumbprint;
        }

        prepareHttpChallenge(hostname, domain, authorization, callback) {
            assert.strictEqual(typeof hostname, 'string');
            assert.strictEqual(typeof domain, 'string');
            assert.strictEqual(typeof authorization, 'object');
            assert.strictEqual(typeof callback, 'function');

            context.log('acmeFlow: challenges: %j', authorization);

            let httpChallenges = authorization.challenges.filter(function (x) { return x.type === 'http-01'; });
            if (httpChallenges.length === 0)
                return callback('no http challenges');

            let challenge = httpChallenges[0];

            context.log('prepareHttpChallenge: preparing for challenge %j', challenge);
            let keyAuthorization = this.getKeyAuthorization(challenge.token);


            this.storeChallengeInKeyVault(challenge, keyAuthorization, callback);
        }

        storeChallengeInKeyVault(challenge, secretData, callback) {
            assert.strictEqual(typeof challenge, 'object');
            assert.strictEqual(typeof secretData, 'string');
            assert.strictEqual(typeof callback, 'function');

            //replace illegal chars for secret name in kv
            let secretName = challenge.token.replace(/([^a-z0-9-]+)/gi, '');

            msRestAzure.loginWithAppServiceMSI({resource: 'https://vault.azure.net'}).then(credentials => {
                const keyVaultClient = new KeyVault.KeyVaultClient(credentials);

                keyVaultClient.setSecret(this.keyVaultUri, secretName, secretData, {})
                    .then(kvSecretBundle => {
                        context.log("KeyVaultSecret id: '" + kvSecretBundle.id + "'.");
                        callback(null, challenge);
                    })
                    .catch(err => {
                        callback('error storing keyvault secret ' + err)
                    });
            })
            .catch(err => {
                callback('error logging in via MSI ' + err)
            });
        }

        prepareChallenge(hostname, domain, authorizationUrl, callback) {
            assert.strictEqual(typeof hostname, 'string');
            assert.strictEqual(typeof domain, 'string');
            assert.strictEqual(typeof authorizationUrl, 'string');
            assert.strictEqual(typeof callback, 'function');

            context.log('prepping challenge');

            const that = this;
            superagent.get(authorizationUrl).timeout(30 * 1000).end(function (error, response) {
                if (error && !error.response)
                    return callback(error);
                if (response.statusCode !== 200)
                    return callback('Invalid response code getting authorization : ' + response.statusCode);

                const authorization = response.body;
                that.prepareHttpChallenge(hostname, domain, authorization, callback);
            });
        }

        notifyChallengeReady(challenge, callback) {
            assert.strictEqual(typeof challenge, 'object'); // { type, status, url, token }
            assert.strictEqual(typeof callback, 'function');

            context.log('notifyChallengeReady: %s was met', challenge.url);

            const keyAuthorization = this.getKeyAuthorization(challenge.token);
            let payload = {
                resource: 'challenge',
                keyAuthorization: keyAuthorization
            };

            this.sendSignedRequest(challenge.url, JSON.stringify(payload), function (error, result) {
                if (error)
                    return callback('Network error when notifying challenge: ' + error.message);
                if (result.statusCode !== 200)
                    return callback(util.format('Failed to notify challenge. Expecting 200, got %s %s', result.statusCode, result.text));
                callback();
            });
        }

        waitForChallenge(challenge, callback) {
            assert.strictEqual(typeof challenge, 'object');
            assert.strictEqual(typeof callback, 'function');

            context.log('waitingForChallenge: %j', challenge);

            // adds timeout for when function app doesn't respect retry interval very rarely
            setTimeout(function() {
                async.retry({ times: 15, interval: 20000 }, function (retryCallback) {
                    context.log('waitingForChallenge: getting status');

                    superagent.get(challenge.url).timeout(30 * 1000).end(function (error, result) {
                        if (error && !error.response) {
                            context.log('waitForChallenge: network error getting uri %s', challenge.url);
                            return retryCallback(error.message); // network error
                        }

                        if (result.statusCode !== 200) {
                            context.log('waitForChallenge: invalid response code getting uri %s', result.statusCode);
                            return retryCallback('Bad response code:' + result.statusCode);
                        }

                        context.log('waitForChallenge: status is "%s %j', result.body.status, result.body);

                        if (result.body.status === 'pending')
                            return retryCallback('not_completed');
                        else if (result.body.status === 'valid')
                            return retryCallback();
                        else
                            return retryCallback('Unexpected status: ' + result.body.status);
                    });
                }, function retryFinished(error) {
                    // async.retry will pass 'undefined' as second arg making it unusable with async.waterfall()
                    callback(error);
                });
            }, 20000);
        }

        acmeFlow(hostname, domain, callback) {
            assert.strictEqual(typeof hostname, 'string');
            assert.strictEqual(typeof domain, 'string');
            assert.strictEqual(typeof callback, 'function');

            if (!fs.existsSync(paths.ACME_ACCOUNT_KEY_FILE)) {
                context.log('getCertificate: generating acme account key on first run');
                this.accountKeyPem = safe.child_process.execSync('openssl genrsa 4096');
                if (!this.accountKeyPem)
                    return callback('cant gen certificate');
                safe.fs.writeFileSync(paths.ACME_ACCOUNT_KEY_FILE, this.accountKeyPem);
            }
            else {
                context.log('getCertificate: using existing acme account key');
                this.accountKeyPem = fs.readFileSync(paths.ACME_ACCOUNT_KEY_FILE);
            }

            let that = this;
            this.registerUser(function (error) {
                if (error)
                    return callback(error);
                that.newOrder(hostname, function (error, order, orderUrl) {
                    if (error)
                        return callback(error);
                    async.eachSeries(order.authorizations, function (authorizationUrl, iteratorCallback) {
                        context.log(`acmeFlow: authorizing ${authorizationUrl}`);
                        that.prepareChallenge(hostname, domain, authorizationUrl, function (error, challenge) {
                            if (error)
                                return iteratorCallback(error);
                            async.waterfall([
                                that.notifyChallengeReady.bind(that, challenge),
                                that.waitForChallenge.bind(that, challenge),
                                that.createKeyAndCsr.bind(that, hostname),
                                that.signCertificate.bind(that, hostname, order.finalize),
                                that.waitForOrder.bind(that, orderUrl),
                                that.downloadCertificate.bind(that, hostname)
                            ], function (error) {
                                iteratorCallback(error);
                                that.cleanupChallenge(hostname, domain, challenge, function (cleanupError) {
                                    if (cleanupError) context.log('acmeFlow: ignoring error when cleaning up challenge:', cleanupError);
                                    iteratorCallback(error);
                                });
                            });
                        });
                    }, callback);
                });
            });
        }

        createKeyAndCsr(hostname, callback) {
            assert.strictEqual(typeof hostname, 'string');
            assert.strictEqual(typeof callback, 'function');

            let outdir = paths.APP_CERTS_DIR;
            const certName = hostname.replace('*.', '_.');
            let csrFile = path.join(outdir, `${certName}.csr`);
            let privateKeyFile = path.join(outdir, `${certName}.key`);

            if (safe.fs.existsSync(privateKeyFile)) {
                // in some old releases, csr file was corrupt. so always regenerate it
                context.log('createKeyAndCsr: reuse the key for renewal at %s', privateKeyFile);
            } else {
                let key = safe.child_process.execSync('openssl genrsa 4096');
                if (!key) return callback('cant generate key');
                if (!safe.fs.writeFileSync(privateKeyFile, key)) return callback('cant write file');

                context.log('createKeyAndCsr: key file saved at %s', privateKeyFile);
            }

            let csrDer = safe.child_process.execSync(`openssl req -new -key ${privateKeyFile} -outform DER -subj /CN=${hostname}`);
            if (!csrDer) return callback('cant generate csr file');
            if (!safe.fs.writeFileSync(csrFile, csrDer)) return callback('cant save csr fle'); // bookkeeping

            context.log('createKeyAndCsr: csr file (DER) saved at %s', csrFile);

            callback(null, csrDer);
        }

        signCertificate(domain, finalizationUrl, csrDer, callback) {
            assert.strictEqual(typeof domain, 'string');
            assert.strictEqual(typeof finalizationUrl, 'string');
            assert(util.isBuffer(csrDer));
            assert.strictEqual(typeof callback, 'function');

            const payload = {
                csr: b64(csrDer)
            };

            context.log('signCertificate: sending sign request');

            this.sendSignedRequest(finalizationUrl, JSON.stringify(payload), function (error, result) {
                if (error) return callback('Network error when signing certificate: ' + error.message);
                // 429 means we reached the cert limit for this domain
                if (result.statusCode !== 200) return callback('Failed to sign certificate. Expecting 200, got ' + result.statusCode + ' ' + result.text);

                return callback(null);
            });
        }

        waitForOrder(orderUrl, callback) {
            assert.strictEqual(typeof orderUrl, 'string');
            assert.strictEqual(typeof callback, 'function');

            context.log(`waitForOrder: ${orderUrl}`);

            async.retry({ times: 15, interval: 20000 }, function (retryCallback) {
                context.log('waitForOrder: getting status');

                superagent.get(orderUrl).timeout(30 * 1000).end(function (error, result) {
                    if (error && !error.response) {
                        context.log('waitForOrder: network error getting uri %s', orderUrl);
                        return retryCallback(error.message); // network error
                    }
                    if (result.statusCode !== 200) {
                        context.log('waitForOrder: invalid response code getting uri %s', result.statusCode);
                        return retryCallback('Bad response code:' + result.statusCode);
                    }

                    context.log('waitForOrder: status is "%s %j', result.body.status, result.body);

                    if (result.body.status === 'pending' || result.body.status === 'processing') return retryCallback('Not completed');
                    else if (result.body.status === 'valid' && result.body.certificate) return retryCallback(null, result.body.certificate);
                    else return retryCallback('Unexpected status or invalid response: ' + result.body);
                });
            }, callback);
        }

        downloadCertificate(hostname, certUrl, callback) {
            assert.strictEqual(typeof hostname, 'string');
            assert.strictEqual(typeof certUrl, 'string');
            assert.strictEqual(typeof callback, 'function');

            let outdir = paths.APP_CERTS_DIR;

            superagent.get(certUrl).buffer().parse(function (res, done) {
                let data = [];
                res.on('data', function (chunk) { data.push(chunk); });
                res.on('end', function () { res.text = Buffer.concat(data); done(); });
            }).timeout(30 * 1000).end(function (error, result) {
                if (error && !error.response) return callback('Network error when downloading certificate');
                if (result.statusCode === 202) return callback('Retry not implemented yet');
                if (result.statusCode !== 200) return callback(util.format('Failed to get cert. Expecting 200, got %s %s', result.statusCode, result.text));

                const fullChainPem = result.text;

                const certName = hostname.replace('*.', '_.');
                let certificateFile = path.join(outdir, `${certName}.cert`);
                if (!safe.fs.writeFileSync(certificateFile, fullChainPem)) return callback('safe error');

                context.log('downloadCertificate: cert file for %s saved at %s', hostname, certificateFile);

                callback();
            });
        }

        cleanupChallenge(hostname, domain, challenge, callback) {
            assert.strictEqual(typeof hostname, 'string');
            assert.strictEqual(typeof domain, 'string');
            assert.strictEqual(typeof challenge, 'object');
            assert.strictEqual(typeof callback, 'function');

            // context.log('cleanupHttpChallenge: unlinking %s', path.join(paths.ACME_CHALLENGES_DIR, challenge.token));

            // fs.unlink(path.join(paths.ACME_CHALLENGES_DIR, challenge.token), callback);
            // todo: remove secret from keyvault
        }

        newOrder(domain, callback) {
            assert.strictEqual(typeof domain, 'string');
            assert.strictEqual(typeof callback, 'function');

            let payload = {
                identifiers: [{
                    type: 'dns',
                    value: domain
                }]
            };

            context.log('newOrder: %s', domain);

            this.sendSignedRequest(this.directory.newOrder, JSON.stringify(payload), function (error, result) {
                if (error)
                    return callback('Network error when registering domain: ' + error.message);
                if (result.statusCode === 403)
                    return callback(result.body.detail);
                if (result.statusCode !== 201)
                    return callback('Failed to register user. Expecting 201');

                context.log('newOrder: created order %s %j', domain, result.body);

                const order = result.body, orderUrl = result.headers.location;

                if (!Array.isArray(order.authorizations))
                    return callback('invalid authorizations in order');

                if (typeof order.finalize !== 'string')
                    return callback('invalid finalize in order');

                if (typeof orderUrl !== 'string')
                    return callback('invalid order location in order header');

                callback(null, order, orderUrl);
            });
        }

        getDirectory(callback) {
            const that = this;
            superagent.get(this.caDirectory).timeout(30 * 1000).end(function (error, response) {
                if (error && !error.response)
                    return callback(error);

                if (response.statusCode !== 200)
                    return callback('Invalid response code when fetching directory : ' + response.statusCode);

                if (typeof response.body.newNonce !== 'string' ||
                    typeof response.body.newOrder !== 'string' ||
                    typeof response.body.newAccount !== 'string')
                    return callback(`Invalid response body : ${response.body}`);

                that.directory = response.body;
                callback(null);
            });
        }

        getCertificate(hostname, domain, callback) {
            assert.strictEqual(typeof hostname, 'string');
            assert.strictEqual(typeof domain, 'string');
            assert.strictEqual(typeof callback, 'function');

            context.log(`getCertificate: start acme flow for ${hostname} from ${this.caDirectory}`);

            const that = this;
            this.getDirectory(function (error) {
                if (error)
                    return callback(error);

                that.acmeFlow(hostname, domain, function (error) {
                    if (error) return callback(error);
                    let outdir = paths.APP_CERTS_DIR;
                    const certName = hostname.replace('*.', '_.');
                    callback(null, path.join(outdir, `${certName}.cert`), path.join(outdir, `${certName}.key`));
                });
            });
        }

        convertCertificate(cert, key, pfx, callback) {
            assert.strictEqual(typeof cert, 'string');
            assert.strictEqual(typeof key, 'string');
            assert.strictEqual(typeof pfx, 'string');
            assert.strictEqual(typeof callback, 'function');

            let randomCertPass  = Math.random().toString(36).slice(-8);

            safe.child_process.execSync('openssl pkcs12 -export -out ' + pfx + ' -inkey ' + key + ' -in ' + cert + ' -passout pass:' + randomCertPass)

            callback(null, pfx, randomCertPass)
        }
    }

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
                    email: process.env.EMAIL_CERT,
                    keyVaultName: process.env.KEYVAULT_NAME,
                    prod: true
                } || {});

                acme.getCertificate(fqdn, fqdn, function (err, cert, key) {
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
