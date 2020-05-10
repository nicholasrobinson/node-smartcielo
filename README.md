# NodeJs interface for smartcielo remote AC control API (MRCOOL)

by Nicholas Robinson

[![mit license](https://badgen.net/badge/license/MIT/red)](https://github.com/nicholasrobinson/node-smartcielo/blob/master/LICENSE)
[![npm](https://badgen.net/npm/v/node-smartcielo)](https://www.npmjs.com/package/node-smartcielo)
[![npm](https://badgen.net/npm/dt/node-smartcielo)](https://www.npmjs.com/package/node-smartcielo)

## Overview

This interace facilitates communication with AC equipment that is connected to the internet by smartcielo. This was specifically developed to facilitate automation of the MRCOOL DIY line of ACs.

## Installation

    $ npm install node-smartcielo
    
## Usage

### Simple Usage

    const SmartCielo = require('./SmartCielo.js');
    const hvac = new SmartCielo(<username>, <password>, <ip_address>);
    hvac.sendPowerOn();
    hvac.sendMode('cool');
    hvac.sendTemperature(75);
    hvac.sendFanSpeed('low');
    console.log('Power:', hvac.getPower(), '| Mode:', hvac.getMode(), '| Fan Speed:', hvac.getFanSpeed(), '| Temperature:', hvac.getTemperature(), '| Room Temperature:', hvac.getRoomTemperature());
    hvac.sendPowerOff()

### Sample Code Execution

    $ node index.js -u <username> -p <password> -i <ip_address> [-v]
    
### Sample Code Output

    Connecting...
    Connected.
    Current State: {"power":"off","temp":75,"mode":"auto","fanspeed":"auto","roomTemperature":75}
    Sent Power On.
    Current State: {"power":"on","temp":"75","mode":"auto","fanspeed":"auto","roomTemperature":83}
    Sent Power Off.
    Current State: {"power":"off","temp":"75","mode":"auto","fanspeed":"auto","roomTemperature":83}
    Exiting...

## References
    
* https://www.mrcool.com/
* https://www.smartcielo.com

## Notes

* The "-v" option will send all communications via an HTTP proxy running on localhost port 8888 for debugging.

Please let me know if you find this useful or come up with any novel implementations.

Enjoy!

Nicholas Robinson

me@nicholassavilerobinson.com

