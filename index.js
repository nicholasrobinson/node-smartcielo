/**
 * Includes
 */
const commandLineArgs = require('command-line-args');
const fetch = require('node-fetch');
const HTMLParser = require('node-html-parser');
const WebSocket = require('ws');

/**
 * Constants
 */
const BASE_URL = 'https://smartcielo.com';
const OPTION_DEFINITIONS = [
    { name: 'username', alias: 'u', type: String },
    { name: 'password', alias: 'p', type: String },
    { name: 'ip', alias: 'i', type: String },
    { name: 'verbose', alias: 'v', type: Boolean }
];
const PROXY = 'http://127.0.0.1:8888';
const OPTIONS = commandLineArgs(OPTION_DEFINITIONS);

/**
 * Debug Proxy Settings
 */
const HttpsProxyAgent = require('https-proxy-agent');
const url = require('url');
const agentOptions = url.parse(PROXY);
const agent = OPTIONS.verbose ? new HttpsProxyAgent(agentOptions) : undefined;
if (agent) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"
}

/**
 * Util Methods
 */

// From: https://stackoverflow.com/questions/18749591/encode-html-entities-in-javascript/39243641#39243641
function unescapeHTML(str) {
    const htmlEntities = {
        nbsp: ' ',
        cent: '¢',
        pound: '£',
        yen: '¥',
        euro: '€',
        copy: '©',
        reg: '®',
        lt: '<',
        gt: '>',
        quot: '"',
        amp: '&',
        apos: '\''
    };
    return str.replace(/\&([^;]+);/g, function (entity, entityCode) {
        let match;
        if (entityCode in htmlEntities) {
            return htmlEntities[entityCode];
        } else if (match = entityCode.match(/^#x([\da-fA-F]+)$/)) {
            return String.fromCharCode(parseInt(match[1], 16));
        } else if (match = entityCode.match(/^#(\d+)$/)) {
            return String.fromCharCode(~~match[1]);
        } else {
            return entity;
        }
    });
};

/**
 * API Logic
 */

async function getSessionCookie() {
    const sessionUrl = BASE_URL + '/';
    const sessionPayload = {
        'agent': agent
    };
    const sessionCookie = await fetch(sessionUrl, sessionPayload)
        .then(response => response.headers.raw()['set-cookie'])
        .then(cookieArray => cookieArray[0].split(';')[0]);
    return sessionCookie;
}

async function getApplicationCookies(username, password, ip, sessionCookie) {
    const loginUrl = BASE_URL + '/auth/login';
    const loginPayload = {
        'agent': agent,
        'headers': {
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': sessionCookie
        },
        'body': 'mobileDeviceName=chrome&deviceTokenId=' + ip + '&timeZone=-07%3A00&state=&client_id=&response_type=&scope=&redirect_uri=&userId=' + username + '&password=' + password + '&rememberMe=false',
        'method': 'POST',
        'redirect': 'manual'
    };
    const applicationCookie = await fetch(loginUrl, loginPayload)
        .then(response => response.headers.raw()['set-cookie'])
        .then(cookieArray => cookieArray[0].split(';')[0])
        .catch(err => Promise.reject('Login failed.'));
    return [sessionCookie, applicationCookie].join(';');
}

async function getAccessCredentials(username, applicationCookies) {
    const tokenUrl = BASE_URL + '/cAcc';
    const tokenPayload = {
        'agent': agent,
        'headers': {
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': applicationCookies
        },
        'body': 'grant_type=password&username=' + username + '&password=undefined',
        'method': 'POST'
    };
    const accessCredentials = await fetch(tokenUrl, tokenPayload)
        .then(response => response.json());
    return accessCredentials;
}

async function getAppUserAndSessionId(applicationCookies) {
    const appUserUrl = BASE_URL + '/home/index';
    const appUserPayload = {
        'agent': agent,
        'headers': {
            'cookie': applicationCookies
        }
    };
    const appUserHtml = await fetch(appUserUrl, appUserPayload)
        .then(response => response.text());
    const root = HTMLParser.parse(appUserHtml);
    const appUserString = root.querySelector('#hdnAppUser').getAttribute('value');
    const appUser = JSON.parse(unescapeHTML(appUserString));
    const sessionId = root.querySelector('#hdnSessionID').getAttribute('value');
    return new Promise(resolve => resolve([appUser, sessionId]));
}

async function getDeviceInfo(sessionId, appUser, accessCredentials) {
    const deviceInfoUrl = BASE_URL + '/api/device/initsubscription';
    const deviceInfoPayload = {
        'agent': agent,
        'headers': {
            'content-type': 'application/json',
            'authorization': accessCredentials.token_type + ' ' + accessCredentials.access_token
        },
        'body': JSON.stringify({
            'userID': appUser.userID,
            'accessToken': appUser.accessToken,
            'expiresIn': accessCredentials.expires_in,
            'sessionId': sessionId
        }),
        'method': 'POST'
    };
    const deviceInfo = await fetch(deviceInfoUrl, deviceInfoPayload)
        .then(response => response.json());
    return deviceInfo;
}

async function negotiateSocketInfo(applicationCookies) {
    const negotiateUrl = BASE_URL + '/signalr/negotiate?clientProtocol=1.5&connectionData=%5B%7B%22name%22%3A%22devicesactionhub%22%7D%5D&_=1588226985637';
    const negotiatePayload = {
        'agent': agent,
        'headers': {
            'cookie': applicationCookies
        }
    };
    const socketInfo = await fetch(negotiateUrl, negotiatePayload)
        .then(response => response.json());
    return socketInfo;
}

/**
 * Main Program
 */

async function initialize(username, password, ip) {
    return getSessionCookie()
        .then(sessionCookie => getApplicationCookies(username, password, ip, sessionCookie))
        .then(applicationCookies => {
            return Promise.all([
                getAccessCredentials(username, applicationCookies),
                getAppUserAndSessionId(applicationCookies)
            ]).then(promiseResults => {
                [accessCredentials, [appUser, sessionId]] = promiseResults;
                return getDeviceInfo(sessionId, appUser, accessCredentials)
                    .then(deviceInfo => {
                        const device = deviceInfo.data.listDevices[0];
                        return negotiateSocketInfo(applicationCookies)
                            .then(socketInfo => {
                                return {
                                    'applicationCookies': applicationCookies,
                                    'socketInfo': socketInfo,
                                    'device': device
                                };
                            })
                    });
            });
        }).catch(err => {
            console.error(err);
            process.exit(1);
        });
}

async function connect(connectionInfo) {
    const ws = new WebSocket(
        'wss://smartcielo.com/signalr/connect?' +
        'transport=webSockets' + '&' +
        'clientProtocol=1.5' + '&' + 'connectionData=%5B%7B%22name%22%3A%22devicesactionhub%22%7D%5D' + '&' +
        'tid=0' + '&' +
        'connectionToken=' + connectionInfo.socketInfo.ConnectionToken,
        {
            'agent': agent,
            'headers': {
                'cookie': connectionInfo.applicationCookies,
                'origin': 'https://smartcielo.com',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'
            }
        }
    );

    ws.on('connection', function (ws) {
        console.log('connection');
        // console.log('connection request cookie: ', ws.upgradeReq.headers.cookie);
    });

    ws.on('open', function open() {
        console.log('open');
        // ws.send('something');
    });

    ws.on('close', function close() {
        console.log('close');
    });

    ws.on('message', function incoming(data) {
        console.log('message');
        console.log(data);
    });

    ws.on('error', function (err) {
        console.log('error', err);
    });
}

initialize(OPTIONS.username, OPTIONS.password, OPTIONS.ip)
    .then(connectionInfo => connect(connectionInfo));
