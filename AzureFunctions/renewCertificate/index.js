const request = require('request');

module.exports = async function (context) {
    var timeStamp = new Date().toISOString();

    const functionAppName = process.env.APPSETTING_WEBSITE_SITE_NAME;
    const functionKey = process.env.reqFnKey;
    const functionName = 'requestCertificate';

    if (functionAppName && functionKey && functionName) {
        context.log(`invoking ${functionName} function`);
        request(`https://${functionAppName}.azurewebsites.net/api/${functionName}?code=${functionKey}`, (error, response, body) => {
            context.log('error:', error);
            context.log('statusCode:', response && response.statusCode);
            context.log('body:', body);
        });
    }
    else {
        context.log(`not all env variables are defined`);
    }

    context.log('Renewal certificate function ran!', timeStamp);
};
