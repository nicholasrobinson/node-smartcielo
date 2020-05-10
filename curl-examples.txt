# 0. Get Session ID

curl -vvv 'https://smartcielo.com/'

# 1. Get Cookie

curl -vvv 'https://smartcielo.com/auth/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: ASP.NET_SessionId=<SESSION_ID>' \
  --data 'mobileDeviceName=chrome&deviceTokenId=<IP_ADDRESS>&timeZone=-07%3A00&state=&client_id=&response_type=&scope=&redirect_uri=&userId=<USERNAME>&password=<PASSWORD>&rememberMe=false'

# 2. Get Access Token

curl 'https://smartcielo.com/cAcc' \
  -H 'content-type: application/x-www-form-urlencoded' \
  -H 'Cookie: ASP.NET_SessionId=<SESSION_ID>; .AspNet.ApplicationCookie=<APPLICATION_COOKIE>' \
  --data 'grant_type=password&username=USERNAME&password=undefined'

# 3. Establish Web Socket

curl 'wss://smartcielo.com/signalr/connect?transport=webSockets&clientProtocol=1.5&connectionToken=Q<ACCESS_TOKEN>>&connectionData=%5B%7B%22name%22%3A%22devicesactionhub%22%7D%5D&tid=7' \
  -H 'Pragma: no-cache' \
  -H 'Origin: https://smartcielo.com' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Sec-WebSocket-Key: <WEB_SOCKET_KEY>' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits' \
  -H 'Cache-Control: no-cache' \
  -H 'Connection: Upgrade' \
  -H 'Sec-WebSocket-Version: 13'

# 4. Send command
  {"H":"devicesactionhub","M":"broadcastActionAC","A":[{"mid":"<SESSION_ID>","mode":"auto","temp":"75","tempValue":"","power":"on","swing":"pos1","fanspeed":"auto","scheduleID":"","macAddress":"<MAC_ADDRESS>","applianceID":<DEVICE_ID>,"performedAction":"power","performedActionValue":"on","actualPower":"off","tempRule":"default","swingRule":"default","fanRule":"default","isSchedule":false,"aSrc":"WEB","ts":1588125459,"deviceTypeVersion":"BI03","deviceType":"BREEZ-I","light":"","rStatus":"","fwVersion":"2.4.2,2.4.1"},{"mid":"","mode":"auto","temp":"75","tempValue":"","power":"off","swing":"pos1","fanspeed":"auto","scheduleID":"","macAddress":"<MAC_ADDRESS>","applianceID":<DEVICE_ID>,"performedAction":"","performedActionValue":"","actualPower":"off","tempRule":"","swingRule":"","fanRule":"","isSchedule":false,"aSrc":"WEB","ts":"","deviceTypeVersion":"","deviceType":"BREEZ-I","light":"","rStatus":"","fwVersion":""}],"I":2}