/**
 * Includes
 */
const commandLineArgs = require('command-line-args');
const url = require('url');
const querystring = require('querystring');
const fetch = require('node-fetch');
const HTMLParser = require('node-html-parser');
const CryptoJS = require('crypto-js');
const WebSocket = require('ws');

/**
 * Constants
 */
const API_HOST = 'smartcielo.com';
const API_HTTP_PROTOCOL = 'https://';
const API_WS_PROTOCOL = 'wss://';
const SESSION_ID_COOKIE = 'ASP.NET_SessionId';
const APPLICATION_COOKIE = '.AspNet.ApplicationCookie'
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

function getCookiesFromResponse(response, cookieName) {
    const cookieArray = response.headers.raw()['set-cookie'];
    return cookieArray.map((element) => element.split(';')[0]).join(';');
}

// From: https://stackoverflow.com/questions/36474899/encrypt-in-javascript-and-decrypt-in-c-sharp-with-aes-algorithm
function decryptString(input) {
    const key = CryptoJS.enc.Utf8.parse('8080808080808080');
    const iv = CryptoJS.enc.Utf8.parse('8080808080808080');
    const output = CryptoJS.AES.decrypt(input, key, {
        FeedbackSize: 128,
        key: key,
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return output.toString(CryptoJS.enc.Utf8);
};

/**
 * API Logic
 */

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
    const applicationCookies = await fetch(loginUrl, loginPayload)
        .then(response => getCookiesFromResponse(response))
        .catch(err => Promise.reject('Login failed.'));
    return applicationCookies;
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
    const appUser = JSON.parse(decryptString(appUserString));
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
        'connectionData': JSON.stringify([{ 'name': 'devicesactionhub' }]),
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
        'connectionToken': connectionInfo.socketInfo.ConnectionToken, 'connectionData': JSON.stringify([{ 'name': 'devicesactionhub' }]),
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

function buildActionCommand(
    temp, macAddress, applianceID,
    isDefault,
    performedAction, performedValue, mid, power, deviceTypeVersion, fwVersion) {
    return {
        'turbo': null,
        'mid': isDefault ? mid : '',
        'mode': 'auto',
        'modeValue': '',
        'temp': String(temp),
        'tempValue': '',
        'power': isDefault ? power : 'off',
        'swing': 'auto',
        'fanspeed': 'auto',
        'scheduleID': '',
        'macAddress': macAddress,
        'applianceID': applianceID,
        'performedAction': isDefault ? performedAction : '',
        'performedActionValue': isDefault ? performedValue : '',
        'actualPower': 'off',
        'modeRule': '',
        'tempRule': isDefault ? 'default' : '',
        'swingRule': isDefault ? 'default' : '',
        'fanRule': isDefault ? 'vanish' : '',
        'isSchedule': false,
        'aSrc': 'WEB',
        'ts': isDefault ? Math.round(Date.now() / 1000) : '',
        'deviceTypeVersion': isDefault ? deviceTypeVersion : '',
        'deviceType': 'BREEZ-I',
        'light': '',
        'rStatus': '',
        'fwVersion': isDefault ? fwVersion : '',
    };
}

function buildPowerPayload(sessionId, macAddress, applianceID) {
    const temp = 76;
    const performedAction = 'power';
    const performedValue = 'on';
    const power = 'on';
    const deviceTypeVersion = 'BI03';
    const fwVersion = '2.4.2,2.4.1';
    return JSON.stringify({
        'H': 'devicesactionhub',
        'M': 'broadcastActionAC',
        'A': [
            buildActionCommand(temp, macAddress, applianceID, true, performedAction, performedValue, sessionId, power, deviceTypeVersion, fwVersion),
            buildActionCommand(temp, macAddress, applianceID, false, performedAction, performedValue, sessionId, power, deviceTypeVersion, fwVersion)
        ],
        'I': 0
    });
}

/**
 * Main Program
 */

async function initialize(username, password, ip) {
    return getApplicationCookies(username, password, ip)
        .then(applicationCookies => {
            return Promise.all([
                getAppUserAndSessionId(applicationCookies),
                getAccessCredentials(username, applicationCookies)
            ]).then(promiseResults => {
                [[appUser, sessionId], accessCredentials] = promiseResults;
                return getDeviceInfo(sessionId, appUser, accessCredentials)
                    .then(deviceInfo => {
                        // FIXME: Assumes only one device.
                        const device = deviceInfo.data.listDevices[0];
                        return negotiateSocketInfo(applicationCookies)
                            .then(socketInfo => {
                                return {
                                    'sessionId': sessionId,
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
        'connectionToken': connectionInfo.socketInfo.ConnectionToken, 'connectionData': JSON.stringify([{ 'name': 'devicesactionhub' }]),
        'tid': 0
    });
    const connectPayload = {
        'agent': agent,
        'headers': {
            'Cookie': connectionInfo.applicationCookies
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

            // REMOVE
            const sendPowerTimer = setTimeout(() => {
                ws.send(buildPowerPayload(connectionInfo.sessionId, connectionInfo.device.macAddress, connectionInfo.device.applianceID));
            }, 5000);
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
