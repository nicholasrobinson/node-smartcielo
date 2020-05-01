/**
 * Includes
 */
const commandLineArgs = require('command-line-args');
const url = require('url');
const querystring = require('querystring');
const fetch = require('node-fetch');
const HTMLParser = require('node-html-parser');
const WebSocket = require('ws');

/**
 * Constants
 */
const API_HOST = 'smartcielo.com';
const API_HTTP_PROTOCOL = 'https://';
const API_WS_PROTOCOL = 'wss://';
const PING_INTERVAL = 5 * 60 * 1000;
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
const agentOptions = url.parse(PROXY);
const agent = OPTIONS.verbose ? new HttpsProxyAgent(agentOptions) : undefined;
if (agent) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
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
    const sessionUrl = new URL(API_HTTP_PROTOCOL + API_HOST + '/');
    const sessionPayload = {
        'agent': agent
    };
    const sessionCookie = await fetch(sessionUrl, sessionPayload)
        .then(response => response.headers.raw()['set-cookie'])
        .then(cookieArray => cookieArray[0].split(';')[0]);
    return sessionCookie;
}

async function getApplicationCookies(username, password, ip, sessionCookie) {
    const loginUrl = new URL(API_HTTP_PROTOCOL + API_HOST + '/auth/login');
    const loginPayload = {
        'agent': agent,
        'headers': {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': sessionCookie
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
    const tokenUrl = new URL(API_HTTP_PROTOCOL + API_HOST + '/cAcc');
    const tokenPayload = {
        'agent': agent,
        'headers': {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': applicationCookies
        },
        'body': 'grant_type=password&username=' + username + '&password=undefined',
        'method': 'POST'
    };
    const accessCredentials = await fetch(tokenUrl, tokenPayload)
        .then(response => response.json());
    return accessCredentials;
}

async function getAppUserAndSessionId(applicationCookies) {
    const appUserUrl = new URL(API_HTTP_PROTOCOL + API_HOST + '/home/index');
    const appUserPayload = {
        'agent': agent,
        'headers': {
            'Cookie': applicationCookies
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
    const deviceInfoUrl = new URL(API_HTTP_PROTOCOL + API_HOST + '/api/device/initsubscription');
    const deviceInfoPayload = {
        'agent': agent,
        'headers': {
            'Content-Type': 'application/json',
            'Authorization': accessCredentials.token_type + ' ' + accessCredentials.access_token
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
    const negotiateUrl = new URL(API_HTTP_PROTOCOL + API_HOST + '/signalr/negotiate');
    negotiateUrl.search = querystring.stringify({
        'connectionData': JSON.stringify([{ "name": "devicesactionhub" }]),
        'clientProtocol': '1.5',
        '_': '1588226985637'
    });
    const negotiatePayload = {
        'agent': agent,
        'headers': {
            'Cookie': applicationCookies
        }
    };
    const socketInfo = await fetch(negotiateUrl, negotiatePayload)
        .then(response => response.json());
    return socketInfo;
}

async function startSocket(connectionInfo) {
    const startUrl = new URL(API_HTTP_PROTOCOL + API_HOST + '/signalr/start');
    startUrl.search = querystring.stringify({
        'transport': 'webSockets',
        'connectionToken': connectionInfo.socketInfo.ConnectionToken, 'connectionData': JSON.stringify([{ "name": "devicesactionhub" }]),
        'clientProtocol': '1.5',
        '_': '1588226985637'
    });
    const startPayload = {
        'agent': agent,
        'headers': {
            'Cookie': connectionInfo.applicationCookies
        }
    };
    const startResponse = await fetch(startUrl, startPayload)
        .then(response => response.json());
    return startResponse;
}

async function pingSocket(applicationCookies) {
    const pingUrl = new URL(API_HTTP_PROTOCOL + API_HOST + '/signalr/ping');
    pingUrl.search = querystring.stringify({
        '_': '1588226985637'
    });
    const pingPayload = {
        'agent': agent,
        'headers': {
            'Cookie': applicationCookies
        }
    };
    const pingResponse = await fetch(pingUrl, pingPayload)
        .then(response => response.json());
    return pingResponse;
}

/**
 * Main Program
 */

async function initialize(username, password, ip) {
    return getSessionCookie()
        .then(sessionCookie => getApplicationCookies(username, password, ip, sessionCookie))
        .then(applicationCookies => {
            return Promise.all([
                getAppUserAndSessionId(applicationCookies),
                getAccessCredentials(username, applicationCookies)
            ]).then(promiseResults => {
                [[appUser, sessionId], accessCredentials] = promiseResults;
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
    const connectUrl = new URL(API_WS_PROTOCOL + API_HOST + '/signalr/connect');
    connectUrl.search = querystring.stringify({
        'transport': 'webSockets',
        'clientProtocol': '1.5',
        'connectionToken': connectionInfo.socketInfo.ConnectionToken, 'connectionData': JSON.stringify([{ "name": "devicesactionhub" }]),
        'tid': 0
    });
    const connectPayload = {
        'agent': agent,
        'headers': {
            'Cookie': connectionInfo.applicationCookies,
            'Origin': 'https://smartcielo.com',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
    };
    const ws = new WebSocket(connectUrl, connectPayload);

    ws.on('connection', function (ws) {
        // REMOVE
        console.log('connection');
    });

    ws.on('open', function open() {
        startSocket(connectionInfo).then(startResponse => {
            const pingTimer = setInterval(() => {
                pingSocket(connectionInfo.applicationCookies);
            }, PING_INTERVAL);
        });
    });

    ws.on('close', function close() {
        // REMOVE
        console.log('close');
    });

    ws.on('message', function incoming(message) {
        const data = JSON.parse(message);
        if (data.M && Array.isArray(data.M) && data.M.length && data.M[0].M && data.M[0].A && Array.isArray(data.M[0].A) && data.M[0].A.length) {
            const method = data.M[0].M;
            const status = data.M[0].A[0];
            switch (method) {
                case 'actionReceivedAC':
                    console.log('power', status.power);
                    console.log('temp', status.temp);
                    console.log('mode', status.mode);
                    console.log('fanspeed', status.fanspeed);
                    break;
                case 'HeartBeatPerformed':
                    console.log('roomTemperature', status.roomTemperature);
                    break;
            }
        }
    });

    ws.on('error', function (err) {
        // REMOVE
        console.log('error', err);
    });
}

initialize(OPTIONS.username, OPTIONS.password, OPTIONS.ip)
    .then(connectionInfo => connect(connectionInfo));
