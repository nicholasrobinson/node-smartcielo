/**
 * Includes
 */
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
const PING_INTERVAL = 5 * 60 * 1000;
const DEFAULT_TEMPERATURE = 75;

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

function buildCommand(
    temp, macAddress, applianceID,
    isAction,
    performedAction, performedValue, mid, deviceTypeVersion, fwVersion) {
    return {
        'turbo': null,
        'mid': isAction ? mid : '',
        'mode': 'auto',
        'modeValue': '',
        'temp': String(temp),
        'tempValue': '',
        'power': performedValue,
        'swing': 'auto',
        'fanspeed': 'auto',
        'scheduleID': '',
        'macAddress': macAddress,
        'applianceID': applianceID,
        'performedAction': isAction ? performedAction : '',
        'performedActionValue': performedValue,
        'actualPower': performedValue,
        'modeRule': '',
        'tempRule': isAction ? 'default' : '',
        'swingRule': isAction ? 'default' : '',
        'fanRule': isAction ? 'default' : '',
        'isSchedule': false,
        'aSrc': 'WEB',
        'ts': isAction ? Math.round(Date.now() / 1000) : '',
        'deviceTypeVersion': isAction ? deviceTypeVersion : '',
        'deviceType': 'BREEZ-I',
        'light': '',
        'rStatus': '',
        'fwVersion': isAction ? fwVersion : '',
    };
}

function buildPowerPayload(sessionId, macAddress, applianceID, powerValue, tempValue) {
    const performedAction = 'power';
    const deviceTypeVersion = 'BI03';
    const fwVersion = '2.4.2,2.4.1';
    return JSON.stringify({
        'H': 'devicesactionhub',
        'M': 'broadcastActionAC',
        'A': [
            buildCommand(tempValue, macAddress, applianceID, true, performedAction, powerValue, sessionId, deviceTypeVersion, fwVersion),
            buildCommand(tempValue, macAddress, applianceID, false, performedAction, powerValue, sessionId, deviceTypeVersion, fwVersion)
        ],
        'I': 0
    });
}

/**
 * API Calls
 */
async function getApplicationCookies(username, password, ip, sessionCookie, agent) {
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

async function getAppUserAndSessionId(applicationCookies, agent) {
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

async function getAccessCredentials(username, applicationCookies, agent) {
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

async function getDeviceInfo(sessionId, appUser, accessCredentials, agent) {
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

async function negotiateSocketInfo(applicationCookies, agent) {
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

async function startSocket(connectionInfo, agent) {
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

async function pingSocket(applicationCookies, agent) {
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
 * Business Logic
 */
async function negotiate(username, password, ip, agent) {
    return getApplicationCookies(username, password, ip, agent)
        .then(applicationCookies => {
            return Promise.all([
                getAppUserAndSessionId(applicationCookies, agent),
                getAccessCredentials(username, applicationCookies, agent)
            ]).then(promiseResults => {
                [[appUser, sessionId], accessCredentials] = promiseResults;
                return getDeviceInfo(sessionId, appUser, accessCredentials, agent)
                    .then(deviceInfo => {
                        // FIXME: Assumes only one device.
                        const device = deviceInfo.data.listDevices[0];
                        return negotiateSocketInfo(applicationCookies, agent)
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

async function connect(connectionInfo, state, agent) {
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

    const sendPowerOn = function (cb, err) {
        return ws.send(buildPowerPayload(connectionInfo.sessionId, connectionInfo.device.macAddress, connectionInfo.device.applianceID, 'on', DEFAULT_TEMPERATURE), cb, err);
    };

    const sendPowerOff = function (cb, err) {
        return ws.send(buildPowerPayload(connectionInfo.sessionId, connectionInfo.device.macAddress, connectionInfo.device.applianceID, 'off', DEFAULT_TEMPERATURE), cb, err);
    };

    return new Promise(function (resolve, reject) {
        ws.on('open', function open() {
            startSocket(connectionInfo, agent).then(startResponse => {
                const pingTimer = setInterval(() => {
                    pingSocket(connectionInfo.applicationCookies, agent);
                }, PING_INTERVAL);
            });
            resolve({
                sendPowerOn: sendPowerOn,
                sendPowerOff: sendPowerOff
            });
        });
        ws.on('close', function close() {
            reject(new Error('Connection Closed.'));
        });
        ws.on('message', function incoming(message) {
            const data = JSON.parse(message);
            if (data.M && Array.isArray(data.M) && data.M.length && data.M[0].M && data.M[0].A && Array.isArray(data.M[0].A) && data.M[0].A.length) {
                const method = data.M[0].M;
                const status = data.M[0].A[0];
                switch (method) {
                    case 'actionReceivedAC':
                        state.power = status.power;
                        state.temp = status.temp;
                        state.mode = status.mode;
                        state.fanspeed = status.fanspeed;
                        break;
                    case 'HeartBeatPerformed':
                        state.roomTemperature = status.roomTemperature;
                        break;
                }
            }
        });
        ws.on('error', function (err) {
            reject(new Error(err));
        });
    });
}

/**
 * Exports
 */
module.exports = class SmartCielo {
    constructor(username, password, ip, agent) {
        this.state = {
            'power': null,
            'temp': null,
            'mode': null,
            'fanspeed': null,
            'roomTemperature': null
        };
        this.waitForConnection = negotiate(username, password, ip, agent)
            .then(connectionInfo => connect(connectionInfo, this.state, agent));
    }

    getState() {
        return this.state;
    }

    sendPowerOn(cb, err) {
        this.waitForConnection.then(promiseResults => {
            return promiseResults.sendPowerOn(cb, err);
        });
    }

    sendPowerOff(cb, err) {
        this.waitForConnection.then(promiseResults => {
            return promiseResults.sendPowerOff(cb, err);
        });
    }
}