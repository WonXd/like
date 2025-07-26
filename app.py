from flask import Flask, request, jsonify
import requests
import threading
import time
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

tokens = {
    '3994059093':'2150B9374CD59EB7C073F00529CF19730FADA395CDEBBEFCB815163752F8E6AD',
'3994059147':'4BD2279EC83B6BC2A4A3A1BE6C36143A01EF1C2C41484077607894DE83A0D8EF',
'3994059180':'972534AADCE01C3A47DB4A17E8B413509A273B80DC7143CACCC3F42F262A62F6',
'3994059216':'C54ADC5ED7985FF0BB0491BA37C92A430F247A3340FBEEEF1ABA5432D1F8030C'
}
def get_jwt_token(uid, password):
    url = f"https://jwt-gen-api-v2.onrender.com/token?uid={uid}&password={password}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'live':
                return data.get('token')
            else:
                print(f"Failed to get JWT token for UID {uid}: Status is not success.")
        else:
            print(f"Failed to get JWT token for UID {uid}: HTTP {response.status_code}")
    except Exception as e:
        print(f"Error getting JWT token for UID {uid}: {e}")
    return None

def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
    return "".join([dec[int((x - int(x)) * 128)]])

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def FOX_RequestAddingFriend(token, target_id):
    url = "https://clientbp.ggblueshark.com/LikeProfile"    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB49",
        "Host": "clientbp.common.ggbluefox.com",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "User-Agent": "Free%20Fire/2019117061 CFNetwork/1399 Darwin/22.1.0",
        "Connection": "keep-alive",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "Accept": "/"
    } 
    data = bytes.fromhex(encrypt_api("08" + Encrypt_ID(target_id) + "1801"))    
    response = requests.post(url, headers=headers, data=data, verify=False)
    if response.status_code == 200:
        return True
    else:
        return False

def send_friend_request_for_token(uid, password, target_id):
    token = get_jwt_token(uid, password)
    if token:
        success = FOX_RequestAddingFriend(token, target_id)
        return success
    return False

@app.route('/likes', methods=['GET'])
def send_friend_requests():
    target_id = request.args.get('uid')
    if not target_id:
        return jsonify({"error": "target_id is required"}), 400

    try:
        target_id = int(target_id)  # تحويل target_id إلى عدد صحيح
    except ValueError:
        return jsonify({"error": "target_id must be an integer"}), 400

    results = {}
    threads = []
    for uid, password in tokens.items():
        thread = threading.Thread(target=lambda u=uid, p=password: results.update({u: send_friend_request_for_token(u, p, target_id)}))
        threads.append(thread)
        thread.start()
        time.sleep(0.1)

    for thread in threads:
        thread.join()

    return jsonify(results)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
