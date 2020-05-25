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
const DEFAULT_POWER = 'off';
const DEFAULT_MODE = 'auto';
const DEFAULT_FAN = 'auto';
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
        'FeedbackSize': 128,
        'key': key,
        'iv': iv,
        'mode': CryptoJS.mode.CBC,
        'padding': CryptoJS.pad.Pkcs7
    });
    return output.toString(CryptoJS.enc.Utf8);
};

function buildCommand(
    temp, power, fanspeed, mode, macAddress, applianceID,
    isAction,
    performedAction, performedValue, mid, deviceTypeVersion, fwVersion) {
    return {
        'turbo': null,
        'mid': isAction ? mid : '',
        'mode': (isAction && performedAction === 'mode') ? performedValue : mode,
        'modeValue': '',
        'temp': (isAction && performedAction === 'temp') ? performedValue : temp,
        'tempValue': '',
        'power': (isAction && performedAction === 'power') ? performedValue : power,
        'swing': (isAction && (performedAction === 'mode' || performedAction === 'temp' || (performedAction === 'power' && performedValue === 'off'))) ? 'Auto' : 'auto',
        'fanspeed': fanspeed,
        'scheduleID': '',
        'macAddress': macAddress,
        'applianceID': applianceID,
        'performedAction': isAction ? performedAction : '',
        'performedActionValue': isAction ? performedValue : '',
        'actualPower': power,
        'modeRule': '',
        'tempRule': isAction ? 'default' : '',
        'swingRule': isAction ? 'default' : '',
        'fanRule': isAction ? ((performedAction === 'power' && performedValue === 'on') ? 'vanish' : 'default') : '',
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

function buildCommandPayload(sessionId, macAddress, applianceID, commandCount, performedAction, performedActionValue, tempValue, power, fanspeed, mode) {
    const deviceTypeVersion = 'BI03';
    const fwVersion = '2.4.2,2.4.1';
    return JSON.stringify({
        'H': 'devicesactionhub',
        'M': 'broadcastActionAC',
        'A': [
            buildCommand(tempValue, power, fanspeed, mode, macAddress, applianceID, true, performedAction, performedActionValue, sessionId, deviceTypeVersion, fwVersion),
            buildCommand(tempValue, power, fanspeed, mode, macAddress, applianceID, false, performedAction, performedActionValue, sessionId, deviceTypeVersion, fwVersion)
        ],
        'I': commandCount
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
        .catch(err => Promise.reject(err));
    return applicationCookies;
}

async function getAppUserAndSessionId(applicationCookies, agent) {
    try {
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
    } catch (err) {
        return Promise.reject(err);
    }
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
            return Promise.reject(err);
        });
}

async function connect(connectionInfo, state, commandCallback, temperatureCallback, errorCallback, agent) {
    return new Promise(function (resolve, reject) {
        try {
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

            const sendMode = function (mode, callback, errorCallback) {
                return ws.send(buildCommandPayload(connectionInfo.sessionId, connectionInfo.device.macAddress, connectionInfo.device.applianceID, state.commandCount++, 'mode', mode, state.temp, state.power, state.fanspeed, state.mode), callback, errorCallback);
            };

            const sendFanSpeed = function (fanspeed, callback, errorCallback) {
                return ws.send(buildCommandPayload(connectionInfo.sessionId, connectionInfo.device.macAddress, connectionInfo.device.applianceID, state.commandCount++, 'fanspeed', fanspeed, state.temp, state.power, state.fanspeed, state.mode), callback, errorCallback);
            };

            const sendTemperature = function (temp, callback, errorCallback) {
                return ws.send(buildCommandPayload(connectionInfo.sessionId, connectionInfo.device.macAddress, connectionInfo.device.applianceID, state.commandCount++, 'temp', temp, state.temp, state.power, state.fanspeed, state.mode), callback, errorCallback);
            };

            const sendPowerOn = function (callback, errorCallback) {
                return ws.send(buildCommandPayload(connectionInfo.sessionId, connectionInfo.device.macAddress, connectionInfo.device.applianceID, state.commandCount++, 'power', 'on', state.temp, state.power, state.fanspeed, state.mode), callback, errorCallback);
            };

            const sendPowerOff = function (callback, errorCallback) {
                return ws.send(buildCommandPayload(connectionInfo.sessionId, connectionInfo.device.macAddress, connectionInfo.device.applianceID, state.commandCount++, 'power', 'off', state.temp, state.power, state.fanspeed, state.mode), callback, errorCallback);
            };

            ws.on('open', function open() {
                startSocket(connectionInfo, agent).then(startResponse => {
                    const pingTimer = setInterval(() => {
                        pingSocket(connectionInfo.applicationCookies, agent)
                            .catch(err => errorCallback(err));
                    }, PING_INTERVAL);
                })
                    .catch(err => reject(err));
                resolve({
                    'sendMode': sendMode,
                    'sendFanSpeed': sendFanSpeed,
                    'sendTemperature': sendTemperature,
                    'sendPowerOn': sendPowerOn,
                    'sendPowerOff': sendPowerOff
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
                            if (commandCallback !== undefined) {
                                commandCallback(status);
                            }
                            break;
                        case 'HeartBeatPerformed':
                            state.roomTemperature = status.roomTemperature;
                            if (temperatureCallback !== undefined) {
                                temperatureCallback(state.roomTemperature);
                            }
                            break;
                    }
                }
            });

            ws.on('error', function (err) {
                reject(err);
            });
        } catch (err) {
            reject(err);
        }
    });
}

/**
 * Exports
 */
module.exports = class SmartCielo {
    constructor(username, password, ip, commandCallback, temperatureCallback, errorCallback, agent) {
        this.state = {
            'power': DEFAULT_POWER,
            'temp': DEFAULT_TEMPERATURE,
            'mode': DEFAULT_MODE,
            'fanspeed': DEFAULT_FAN,
            'roomTemperature': DEFAULT_TEMPERATURE,
            'commandCount': 0
        };
        this.connectionError = undefined;
        this.waitForConnection = negotiate(username, password, ip, agent)
            .then(connectionInfo => connect(connectionInfo, this.state, commandCallback, temperatureCallback, errorCallback, agent))
            .catch(err => {
                this.connectionError = err;
                errorCallback(err);
            });
    }

    getState() {
        if (this.connectionError) {
            throw new Error('Not Connected.');
        }
        return this.state;
    }

    getPower() {
        if (this.connectionError) {
            throw new Error('Not Connected.');
        }
        return this.state.power;
    }

    getMode() {
        if (this.connectionError) {
            throw new Error('Not Connected.');
        }
        return this.state.mode;
    }

    getFanSpeed() {
        if (this.connectionError) {
            throw new Error('Not Connected.');
        }
        return this.state.fanspeed;
    }

    getTemperature() {
        if (this.connectionError) {
            throw new Error('Not Connected.');
        }
        return this.state.temp;
    }

    getRoomTemperature() {
        if (this.connectionError) {
            throw new Error('Not Connected.');
        }
        return this.state.roomTemperature;
    }

    sendMode(mode, callback, errorCallback) {
        if (this.connectionError) {
            throw new Error('Not Connected.');
        }
        this.waitForConnection.then(promiseResults => {
            return promiseResults.sendMode(mode, callback, errorCallback);
        }).catch(err => errorCallback(err));
    }

    sendFanSpeed(fanspeed, callback, errorCallback) {
        if (this.connectionError) {
            throw new Error('Not Connected.');
        }
        this.waitForConnection.then(promiseResults => {
            return promiseResults.sendFanSpeed(fanspeed, callback, errorCallback);
        }).catch(err => errorCallback(err));
    }

    sendTemperature(temp, callback, errorCallback) {
        if (this.connectionError) {
            throw new Error('Not Connected.');
        }
        this.waitForConnection.then(promiseResults => {
            return promiseResults.sendTemperature(temp, callback, errorCallback);
        }).catch(err => errorCallback(err));
    }

    sendPowerOn(callback, errorCallback) {
        if (this.connectionError) {
            throw new Error('Not Connected.');
        }
        this.waitForConnection.then(promiseResults => {
            return promiseResults.sendPowerOn(callback, errorCallback);
        }).catch(err => errorCallback(err));
    }

    sendPowerOff(callback, errorCallback) {
        if (this.connectionError) {
            throw new Error('Not Connected.');
        }
        this.waitForConnection.then(promiseResults => {
            return promiseResults.sendPowerOff(callback, errorCallback);
        }).catch(err => errorCallback(err));
    }
}
