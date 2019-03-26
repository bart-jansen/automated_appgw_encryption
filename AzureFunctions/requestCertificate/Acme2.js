'use strict';

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

let helpers = require('./helpers');

const paths = {
    ACME_ACCOUNT_KEY_FILE: './acme.key',
    APP_CERTS_DIR: './'
};

const CA_PROD_DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory',
    CA_STAGING_DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory';

module.exports = class Acme2 {
    constructor(options) {
        assert.strictEqual(typeof options, 'object');
        this.context = options.context;
        this.accountKeyPem = null; // Buffer
        this.email = options.email;
        this.keyVaultUri = `https://${options.keyVaultName}.vault.azure.net/`;
        this.keyId = null;
        this.caDirectory = options.prod ? CA_PROD_DIRECTORY_URL : CA_STAGING_DIRECTORY_URL;
        this.directory = {};
    }

    logMsg(msg) {
        if(this.context) this.context.log(msg);
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
                e: helpers.b64(Buffer.from([0x01, 0x00, 0x01])),
                kty: 'RSA',
                n: helpers.b64(helpers.getModulus(this.accountKeyPem))
            };
        }

        let payload64 = helpers.b64(payload);

        this.getNonce((error, nonce) => {
            if (error)
                return callback(error);

            this.logMsg(`sendSignedRequest: using nonce ${nonce} for url ${url}`);

            let protected64 = helpers.b64(JSON.stringify(_.extend({}, header, { nonce: nonce })));
            let signer = crypto.createSign('RSA-SHA256');
            signer.update(protected64 + '.' + payload64, 'utf8');
            let signature64 = helpers.urlBase64Encode(signer.sign(this.accountKeyPem, 'base64'));
            let data = {
                protected: protected64,
                payload: payload64,
                signature: signature64
            };

            superagent.post(url).set('Content-Type', 'application/jose+json').set('User-Agent', 'acme-function').send(JSON.stringify(data)).timeout(30 * 1000).end(function (error, res) {
                if (error && !error.response)
                    return callback(error); // network errors
                callback(null, res);
            });
        });
    }

    updateContact(registrationUri, callback) {
        assert.strictEqual(typeof registrationUri, 'string');
        assert.strictEqual(typeof callback, 'function');

        this.logMsg(`updateContact: registrationUri: ${registrationUri} email: ${this.email}`);

        // https://github.com/ietf-wg-acme/acme/issues/30
        const payload = {
            contact: ['mailto:' + this.email]
        };

        this.sendSignedRequest(registrationUri, JSON.stringify(payload), (error, result) => {
            if (error)
                return callback('Network error when registering user: ' + error.message);
            if (result.statusCode !== 200)
                return callback('Failed to update contact. Expecting 200 got ' + result.statusCode);

            this.logMsg(`updateContact: contact of user updated to ${this.email}`);
            callback();
        });
    }

    registerUser(callback) {
        assert.strictEqual(typeof callback, 'function');

        let payload = {
            termsOfServiceAgreed: true
        };

        this.logMsg('registerUser: registering user');

        this.sendSignedRequest(this.directory.newAccount, JSON.stringify(payload), (error, result) => {
            if (error)
                return callback('Network error when registering new account: ' + error.message);
            // 200 if already exists. 201 for new accounts
            if (result.statusCode !== 200 && result.statusCode !== 201)
                return callback('Failed to register new account. Expecting 200 or 201');
            this.logMsg(`registerUser: user registered keyid: ${result.headers.location}`);
            this.keyId = result.headers.location;
            this.updateContact(result.headers.location, callback);
        });
    }

    getKeyAuthorization(token) {
        assert(util.isBuffer(this.accountKeyPem));

        let jwk = {
            e: helpers.b64(Buffer.from([0x01, 0x00, 0x01])),
            kty: 'RSA',
            n: helpers.b64(helpers.getModulus(this.accountKeyPem))
        };

        let shasum = crypto.createHash('sha256');
        shasum.update(JSON.stringify(jwk));
        let thumbprint = helpers.urlBase64Encode(shasum.digest('base64'));

        return token + '.' + thumbprint;
    }

    prepareHttpChallenge(hostname, authorization, callback) {
        assert.strictEqual(typeof hostname, 'string');
        assert.strictEqual(typeof authorization, 'object');
        assert.strictEqual(typeof callback, 'function');

        this.logMsg('acmeFlow: challenges: ' + JSON.stringify(authorization));

        let httpChallenges = authorization.challenges.filter(function (x) { return x.type === 'http-01'; });
        if (httpChallenges.length === 0)
            return callback('no http challenges');

        let challenge = httpChallenges[0];

        this.logMsg('prepareHttpChallenge: preparing for challenge ' + JSON.stringify(challenge));
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
                    this.logMsg("KeyVaultSecret id: '" + kvSecretBundle.id + "'.");
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

    prepareChallenge(hostname, authorizationUrl, callback) {
        assert.strictEqual(typeof hostname, 'string');
        assert.strictEqual(typeof authorizationUrl, 'string');
        assert.strictEqual(typeof callback, 'function');

        this.logMsg('prepping challenge');

        superagent.get(authorizationUrl).timeout(30 * 1000).end((error, response) => {
            if (error && !error.response)
                return callback(error);
            if (response.statusCode !== 200)
                return callback('Invalid response code getting authorization : ' + response.statusCode);

            const authorization = response.body;
            this.prepareHttpChallenge(hostname, authorization, callback);
        });
    }

    notifyChallengeReady(challenge, callback) {
        assert.strictEqual(typeof challenge, 'object'); // { type, status, url, token }
        assert.strictEqual(typeof callback, 'function');

        this.logMsg('notifyChallengeReady: ' + challenge.url + ' was met');

        const keyAuthorization = this.getKeyAuthorization(challenge.token);
        let payload = {
            resource: 'challenge',
            keyAuthorization: keyAuthorization
        };

        this.sendSignedRequest(challenge.url, JSON.stringify(payload), function (error, result) {
            if (error)
                return callback('Network error when notifying challenge: ' + error.message);
            if (result.statusCode !== 200)
                return callback('Failed to notify challenge. Expecting 200, got ' + result.statusCode + ' ' + result.text);
            callback();
        });
    }

    waitForChallenge(challenge, callback) {
        assert.strictEqual(typeof challenge, 'object');
        assert.strictEqual(typeof callback, 'function');

        this.logMsg('waitingForChallenge: ' + JSON.stringify(challenge));

       async.retry({ times: 15, interval: 20000 }, (retryCallback) => {
            this.logMsg('waitingForChallenge: getting status');

            superagent.get(challenge.url).timeout(30 * 1000).end( (error, result) => {
                if (error && !error.response) {
                    this.logMsg('waitForChallenge: network error getting uri ' + challenge.url);
                    return retryCallback(error.message); // network error
                }

                if (result.statusCode !== 200) {
                    this.logMsg('waitForChallenge: invalid response code getting uri ' + result.statusCode);
                    return retryCallback('Bad response code:' + result.statusCode);
                }

                this.logMsg('waitForChallenge: status is ' + result.body.status + ' ' + JSON.stringify(result.body));

                if (result.body.status === 'pending') {
                    return retryCallback('not_completed');
                }
                else if (result.body.status === 'valid') {
                    return retryCallback();
                }
                else {
                    return retryCallback('Unexpected status: ' + result.body.status);
                }
            });
        }, (error) => {
            // async.retry will pass 'undefined' as second arg making it unusable with async.waterfall()
            callback(error);
        });
    
    }

    acmeFlow(hostname, callback) {
        assert.strictEqual(typeof hostname, 'string');
        assert.strictEqual(typeof callback, 'function');

        if (!fs.existsSync(paths.ACME_ACCOUNT_KEY_FILE)) {
            this.logMsg('getCertificate: generating acme account key on first run');
            this.accountKeyPem = safe.child_process.execSync('openssl genrsa 4096');
            if (!this.accountKeyPem)
                return callback('cant gen certificate');
            safe.fs.writeFileSync(paths.ACME_ACCOUNT_KEY_FILE, this.accountKeyPem);
        }
        else {
            this.logMsg('getCertificate: using existing acme account key');
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
                    that.logMsg(`acmeFlow: authorizing ${authorizationUrl}`);
                    that.prepareChallenge(hostname, authorizationUrl, function (error, challenge) {
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
                            that.cleanupChallenge(hostname, challenge, function (cleanupError) {
                                if (cleanupError) that.logMsg('acmeFlow: ignoring error when cleaning up challenge' + cleanupError);
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
            this.logMsg('createKeyAndCsr: reuse the key for renewal at ' + privateKeyFile);
        } else {
            let key = safe.child_process.execSync('openssl genrsa 4096');
            if (!key) return callback('cant generate key');
            if (!safe.fs.writeFileSync(privateKeyFile, key)) return callback('cant write file');

            this.logMsg('createKeyAndCsr: key file saved at ' + privateKeyFile);
        }

        let csrDer = safe.child_process.execSync(`openssl req -new -key ${privateKeyFile} -outform DER -subj /CN=${hostname}`);
        if (!csrDer) return callback('cant generate csr file');
        if (!safe.fs.writeFileSync(csrFile, csrDer)) return callback('cant save csr fle'); // bookkeeping

        this.logMsg('createKeyAndCsr: csr file (DER) saved at ' + csrFile);

        callback(null, csrDer);
    }

    signCertificate(hostname, finalizationUrl, csrDer, callback) {
        assert.strictEqual(typeof hostname, 'string');
        assert.strictEqual(typeof finalizationUrl, 'string');
        assert(util.isBuffer(csrDer));
        assert.strictEqual(typeof callback, 'function');

        const payload = {
            csr: helpers.b64(csrDer)
        };

        this.logMsg('signCertificate: sending sign request');

        this.sendSignedRequest(finalizationUrl, JSON.stringify(payload), function (error, result) {
            if (error) return callback('Network error when signing certificate: ' + error.message);
            // 429 means we reached the cert limit for this hostname
            if (result.statusCode !== 200) return callback('Failed to sign certificate. Expecting 200, got ' + result.statusCode + ' ' + result.text);

            return callback(null);
        });
    }

    waitForOrder(orderUrl, callback) {
        assert.strictEqual(typeof orderUrl, 'string');
        assert.strictEqual(typeof callback, 'function');

        this.logMsg(`waitForOrder: ${orderUrl}`);

        async.retry({ times: 15, interval: 20000 }, (retryCallback) => {
            this.logMsg('waitForOrder: getting status');

            superagent.get(orderUrl).timeout(30 * 1000).end( (error, result) => {
                if (error && !error.response) {
                    this.logMsg('waitForOrder: network error getting uri ' + orderUrl);
                    return retryCallback(error.message); // network error
                }
                if (result.statusCode !== 200) {
                    this.logMsg('waitForOrder: invalid response code getting uri ' + result.statusCode);
                    return retryCallback('Bad response code:' + result.statusCode);
                }

                this.logMsg('waitForOrder: status is ' + result.body.status + ' ' + JSON.stringify(result.body));

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
        }).timeout(30 * 1000).end((error, result) => {
            if (error && !error.response) return callback('Network error when downloading certificate');
            if (result.statusCode === 202) return callback('Retry not implemented yet');
            if (result.statusCode !== 200) return callback('Failed to get cert. Expecting 200, got ' + result.statusCode + ' ' + result.text);

            const fullChainPem = result.text;

            const certName = hostname.replace('*.', '_.');
            let certificateFile = path.join(outdir, `${certName}.cert`);
            if (!safe.fs.writeFileSync(certificateFile, fullChainPem)) return callback('safe error');

            this.logMsg(`downloadCertificate: cert file for ${hostname} saved at ${certificateFile}`);

            callback();
        });
    }

    cleanupChallenge(hostname, challenge, callback) {
        assert.strictEqual(typeof hostname, 'string');
        assert.strictEqual(typeof challenge, 'object');
        assert.strictEqual(typeof callback, 'function');

        // this.logMsg('cleanupHttpChallenge: unlinking %s', path.join(paths.ACME_CHALLENGES_DIR, challenge.token));

        // fs.unlink(path.join(paths.ACME_CHALLENGES_DIR, challenge.token), callback);
        // todo: remove secret from keyvault
    }

    newOrder(hostname, callback) {
        assert.strictEqual(typeof hostname, 'string');
        assert.strictEqual(typeof callback, 'function');

        let payload = {
            identifiers: [{
                type: 'dns',
                value: hostname
            }]
        };

        this.logMsg('newOrder: ' + hostname);

        this.sendSignedRequest(this.directory.newOrder, JSON.stringify(payload), (error, result) => {
            if (error)
                return callback('Network error when registering hostname: ' + error.message);
            if (result.statusCode === 403)
                return callback(result.body.detail);
            if (result.statusCode !== 201)
                return callback('Failed to register user. Expecting 201');

            this.logMsg('newOrder: created order ' + hostname + ' ' + JSON.stringify(result.body));

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
        superagent.get(this.caDirectory).timeout(30 * 1000).end( (error, response) => {
            if (error && !error.response)
                return callback(error);

            if (response.statusCode !== 200)
                return callback('Invalid response code when fetching directory : ' + response.statusCode);

            if (typeof response.body.newNonce !== 'string' ||
                typeof response.body.newOrder !== 'string' ||
                typeof response.body.newAccount !== 'string')
                return callback(`Invalid response body : ${response.body}`);

            this.directory = response.body;
            callback(null);
        });
    }

    getCertificate(hostname, callback) {
        assert.strictEqual(typeof hostname, 'string');
        assert.strictEqual(typeof callback, 'function');

        this.logMsg(`getCertificate: start acme flow for ${hostname} from ${this.caDirectory}`);

        this.getDirectory(dirError => {
            if (dirError)
                return callback(dirError);

            this.acmeFlow(hostname, (error) => {
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