# NodeJs interface for smartcielo remote AC control API (MRCOOL)

by Nicholas Robinson

## Overview

This interace facilitates communication with AC equipment that is connected to the internet by smartcielo. This was specifically developed to facilitate automation of the MRCOOL DIY line of ACs.

## Installation

    $ git clone git://github.com/nicholasrobinson/node-smartcielo.git
    $ cd node-smartcielo
    $ npm install
    
## Usage

### Execution

    $ node index.js -u <username> -p <password> -i <ip_address> [-v]
    
### Sample Output

    Connecting...
    Connected.
    Current State: {"power":null,"temp":null,"mode":null,"fanspeed":null,"roomTemperature":null}
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

