
const fs = require('fs');

module.exports = function (context, req) {
    if(context && context.bindingData && context.bindingData.code) {
        const responseFilePath = context.bindingData.code;

        context.log(`Checking for ACME challenge response at '${responseFilePath}'...`);

        fs.exists(responseFilePath, function (exists) {
            if (!exists) {
                context.log(`ACME challenge response file '${responseFilePath}' not found.`);

                context.res = {
                    status: 404,
                    headers: { "Content-Type": "text/plain" },
                    body: 'ACME challenge response not found.'
                };

                context.done();
                return;
            }

            context.log(`ACME challenge response file '${responseFilePath}' found. Reading file...`);
            fs.readFile(responseFilePath, 'utf-8', (error, data) => {
                if (error) {
                    context.log.error(`An error occured while reading file '${responseFilePath}'.`, error);
                    context.res = { status: 500 }; 
                    context.done();
                    return;
                }

                context.log(`ACME challenge response file '${responseFilePath}' read successfully.`);
                context.log(data);
                context.res = {
                    status: 200,
                    headers: { "Content-Type": "text/plain" },
                    body: data
                };

                context.done();
            });
        });
    }
    else {
        context.log('No challenge code supplied');
        context.res = {
            status: 404,
            headers: { "Content-Type": "text/plain" },
            body: 'No challenge code supplied'
        };

        context.done();
    }
};