import os
import time
import hmac
import json
import struct
import base64
import requests
from hashlib import sha1

symbols = '23456789BCDFGHJKMNPQRTVWXY'
server_time = 0
timeout = 0

def getQueryTime():
    try:
        if(timeout <= time.time() - 1):
            request = requests.post('https://api.steampowered.com/ITwoFactorService/QueryTime/v0001', timeout=30)
            json=request.json()
            server_time = int(json['response']['server_time']) - time.time()
            timeout = time.time()
        return server_time
    except:
        return 0

def getGuardCode(shared_secret):
    code = ''
    timestamp = time.time() + getQueryTime()
    _hmac = hmac.new(base64.b64decode(shared_secret), struct.pack('>Q', int(timestamp/30)), sha1).digest()
    _ord = ord(_hmac[19:20]) & 0xF
    value = struct.unpack('>I', _hmac[_ord:_ord+4])[0] & 0x7fffffff
    for i in range(5):
        code += symbols[value % len(symbols)]
        value = int(value / len(symbols))
    return code

if __name__ == "__main__":
    if (not os.listdir("./mafiles/")):
        print("Directory is empty")

    with os.scandir("./mafiles/") as files:
        for file in files:
            if file.is_file() and file.name.endswith('.maFile'):
                with open(file, 'r') as file:
                    data = json.loads(file.read())
                    print(
                        f"Username: {data['account_name']}\n"\
                        f"SteamId: {data['Session']['SteamID']}\n"\
                        f"GuardCode: {getGuardCode(data['shared_secret'])}\n"\
                    )