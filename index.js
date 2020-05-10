/**
 * Includes
 */
const commandLineArgs = require('command-line-args');
const SmartCielo = require('./SmartCielo.js');

/**
 * Constants
 */

const OPTION_DEFINITIONS = [
    { name: 'username', alias: 'u', type: String },
    { name: 'password', alias: 'p', type: String },
    { name: 'ip', alias: 'i', type: String },
    { name: 'verbose', alias: 'v', type: Boolean }
];
const OPTIONS = commandLineArgs(OPTION_DEFINITIONS);

/**
 * Debug Proxy Settings
 */
const HttpsProxyAgent = require('https-proxy-agent');
const url = require('url');
const PROXY = 'http://127.0.0.1:8888';
const agentOptions = url.parse(PROXY);
const agent = OPTIONS.verbose ? new HttpsProxyAgent(agentOptions) : undefined;
if (agent) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

/**
 * Example Usage.
 */
const hvac = new SmartCielo(OPTIONS.username, OPTIONS.password, OPTIONS.ip, agent);
console.log('Connecting...');
hvac.waitForConnection.then(_ => {
    console.log('Connected.');
    console.log('Current State:', JSON.stringify(hvac.getState()));
    hvac.sendPowerOn(_ => {
        console.log('Sent Power On.');
        setTimeout(() => {
            console.log('Current State:', JSON.stringify(hvac.getState()));
            hvac.sendPowerOff(_ => {
                console.log('Sent Power Off.');
                setTimeout(() => {
                    console.log('Current State:', JSON.stringify(hvac.getState()));
                    console.log('Exiting...');
                    process.exit();
                }, 1000);
            }, err => {
                console.error(err);
            });
        }, 10000);
    }, err => {
        console.error(err);
    });
}, err => {
    console.error(err);
});
