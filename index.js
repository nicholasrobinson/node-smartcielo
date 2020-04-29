/**
 * Includes
 */
const commandLineArgs = require('command-line-args');
const fetch = require('node-fetch');
const HTMLParser = require('node-html-parser');

/**
 * Constants
 */
const BASE_URL = 'https://smartcielo.com';
const OPTION_DEFINITIONS = [
    { name: 'username', alias: 'u', type: String },
    { name: 'password', alias: 'p', type: String },
    { name: 'ip', alias: 'i', type: String }
];

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
    const sessionCookie = await fetch(sessionUrl)
        .then(response => response.headers.raw()['set-cookie'])
        .then(cookieArray => cookieArray[0].split(';')[0]);
    return sessionCookie;
}

async function getApplicationCookies(username, password, ip, sessionCookie) {
    const loginUrl = BASE_URL + '/auth/login';
    const loginPayload = {
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
        .catch(err => Promise.reject("Login failed."));
    return [sessionCookie, applicationCookie].join(';');
}

async function getAccessCredentials(username, applicationCookies) {
    const tokenUrl = BASE_URL + '/cAcc';
    const tokenPayload = {
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

function initialize(username, password, ip) {
    getSessionCookie()
        .then(sessionCookie => getApplicationCookies(username, password, ip, sessionCookie))
        .then(applicationCookies => {
            Promise.all([
                getAccessCredentials(username, applicationCookies),
                getAppUserAndSessionId(applicationCookies)
            ]).then(promiseResults => {
                [accessCredentials, [appUser, sessionId]] = promiseResults;
                getDeviceInfo(sessionId, appUser, accessCredentials)
                    .then(deviceInfo => {
                        const device = deviceInfo.data.listDevices[0];
                        negotiateSocketInfo(applicationCookies)
                            .then(socketInfo => console.log(socketInfo));
                    });
            });
        }).catch(err => {
            console.error(err);
            process.exit(1);
        });
}

const options = commandLineArgs(OPTION_DEFINITIONS);
initialize(options.username, options.password, options.ip);
