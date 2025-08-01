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
    '3994059216':'C54ADC5ED7985FF0BB0491BA37C92A430F247A3340FBEEEF1ABA5432D1F8030C',
    '3994059253':'3F8BD3C7D91D6C4583E80757B0D8C0B15D9316E096064D92EA42875498371A9E',
    '3994059289':'F0C5514E9F175316C5FA59EBE88AB247254EC854CB7D574412EA91BE625CA2C9',
    '3994059360':'CE2E08CAE81ED5C3ED1BA7DB4CF761D18D10F32D88321E1FA684740190C119D9',
    '3994059384':'DDC6B2A9098969B13E89CC484924F4D25C3C2C81EE1A121EA91DC75625040A1E',
    '3994059411':'91EF51895B66057AFEE8926F123BE712AC964FAEF9C9DB1A4C2E58DB36DD3E31',
    '3994059452':'39E7FDBE9D5C14FD7504AD750AD3CD7B4132AE02800AB532017D6E2C4608C911',
    '3994059490':'48F5759998168A03EE67FCA430D940348F850215A33F89BE0B8B1B08B4C82208',
    '3994059517':'1D4C6609E9500DBF8EF3D759A2F861595D4A7DBDFE16DF50EB0D8C5FD01AA7CB',
    '3994059546':'9150A16E62EF31F4E2F677D57F7945952D28646643C2BF77F9D7006EE562DC96',
    '3994059576':'EFEDE0CB79BC79257D22C8FA0E42D664DC7773729E9793877DFAE4B66D7E5893',
    '3994059606':'EC54300F68D7053CDAFFC534C1362A56D8291C5B60E248162DA2B284076606E0',
    '3994059640':'5909ADCA13349E34C37AF3C7F6E4F6BF156C9423CB5A5CEE6C47002646B9C159',
    '3994059659':'6E801AD8EF8F54C56B5BC7DD720CE705CC1353F49C95697065FE8080C3E93B70',
    '3994059689':'42C6DB5830CF3CAC0C643816DD0CEFA99499B91433076A5EB1F99325D6DF250C',
    '3994059717':'8A604B8EAF3F12763A81ABEABBDFE4E8D28F5225C71F2339453E75FAEE9A6078',
    '3994059747':'10B3859CEA22EB83A56567F29083E90E69D59BCC8705965AD22E4CD8C5983A13',
    '3994059792':'73D0A9FB042D35C3C90DB9AF59C808E21C228387607F3225035A6B9D6556E416',
    '3994059836':'35FC54D5AFCDE454348007C738F951F34F271C4CE7BEDD527B4F724E8EA9BC07',
    '3994059874':'269C4359CD375E81EDE1655CC3C78CE6D4D820B42BD127ED7E7FAF44645158D1',
    '3994059905':'360DA0598F94933DBC571130ECCC29D4CEE36954439119B2A25FFE2CF223E880',
    '3994059948':'C923CB8DA863B9F1C167E2BB3F6748BB167B58F11ED4509C32979DEEC9BD201C',
    '3994059989':'4440C616864AA38919BF59945F98EACF6521062C98A21C109D43924CBB36A870',
    '3994060012':'4E6F60E3911A4B23EFF740BAA53EF9793C736393CA6EBE61B8E18BC7502A044B',
    '3994060037':'4E4E37D8D36776C263F706018155FF25E170CCCFD66C15F6DB50BDAF85F1C9B3',
    '3994060070':'22E94D656FCE639515CD9C4193AA418BF2121294A7AB26BB7A62632121C21411',
    '3994060088':'CE19345714A523C558644371DD2B60EC55FF7AF0C05029228F332373B63FD8F8',
    '3994060140':'DF49422DD44C509929CCD537C3A9BAF60A4E1047B45C91D591717AE53960B0BC',
    '3994060174':'772DEC5BD7D0A2401EA9340BBBF6364DA0BA9F4C4656E713D4E73A5D5B98ABBA',
    '3994060193':'5C05B4A4CA8CB99CB8F52D3CB2A57CED136EFC75863A7126E82983BA3A029FFF',
    '3994060222':'DC65C7AAD6EF7110090D3A77F05706F153022AE363F4FA2B25B9939E46A67116',
    '3994060251':'E7677C37772AC05C38F34F9F434358A586A584A94D4EB72FBDB4C533FFA38720',
    '3994060269':'A74F14A83FDCBBD1AFBA74AFC99EE0A39C088DD3D787A56FF1A63AFD848A99E8',
    '3994060309':'282CFD3E98ABB5C47B3C508AAED65F84C7622E88375BE8AD7411FEEEB376ACBD',
    '3994060345':'DE28509EF6DEDFCDAC87C0765F30A9647727775123B81C6B22CF864FBBBF6F13',
    '3994060390':'3BEC070A17F7A7068B777BFE070DBA63E612339E887917F9A9B7AD8344B9EFD3',
    '3994060495':'2E0E8DCDB063445EFB912077DB76DDB6DDBF611692BA8B7503BD5D42A4AE5703',
    '3994060623':'264AF9539E080149EC662A58754FFCE9D29EBE0F573728C0331AA24625BAB8F1',
    '3994060667':'FDED83D7E3FF10A5ADB196D307E572F4120FC918734CF9122C8491912FDE8542',
    '3994060696':'9426AF2428FECA4A0CCB0A8E40A26F1279308A465BA6AEC6AC517DDBA169E765',
    '3994060727':'5391315F33A67104DCA36F3532C46CCD6B2B1138D02F8B64CF8A47EBFF20B513',
    '3994060799':'658A194B638DAD2CC6BE98BE8D503884FD73A64582CCBD4970CDAEC043222CB6',
    '3994060837':'5A36771779A6ABA3785C4F0FFA5FB4564024BD441AF082A34C6A6DFCA729B331',
    '3994060899':'E9A87BE5E376108BF1C9E1A4AF9E1CD813C0FC012EF388CF58C07DBC88512CDE',
    '3994060923':'1B7A2952781CF2FE89E0AE96E2E1232B7CC6D0B4B75F2DFB9072BD608FA30275',
    '3994060950':'C0435999FBC215B5D7FE56110F69DC6A568B6B3C6B5F062D4E43FCA4B72AA73C',
    '3994060971':'DB78ACF1547F04D720AEEC518889A4A0B6996FB515D94B4BF02DEDDBFAD3A424',
    '3994060997':'D00F91F0B43F210FB61D750E5CF4118AED6238B88A74CDEAAB91D00CE5A40B88',
    '3994061029':'1E0B27147EED4CBC8B4DC87288ED4FA73333324342782DCE08399B082608BB2F',
    '3994061063':'FC87BF951A4EFA0285175E1FA21090C9EBF71BAB06DC8D3E22CD7BDF756DE8ED',
    '3994061127':'389A955C86CF5B8FC06EF93BD2A0919D3E7D827E037607998108AF5486AFB8A5',
    '3994061157':'1D4ABE3758E57145303B80D2F26CB588D5F3DD3FB5BAA340D150D6EB75D92169',
    '3994061199':'7C479C43DE43E260101BED72760DFDCF40D3EAC3B8BB43EF068C82320E6F4375',
    '3994061323':'EFE51D949AB265B9133FCC2E3835ED651DDEF62D736AE98CB4352C1DDC3A935C',
    '3994061357':'F9A3AD84D839CD165C7EEFDBE8CA8E3C552D3E671293E75AC8F83FC990A50EC4',
    '3994061392':'252C09CD44B67F7064EC973986CDA40B4216CACC434738242013B47CC58930A0',
    '3994061428':'5C2FB096B342E12B032BA1EBE39706316967977FE2A363B147F57B1DEF112E1F',
    '3994061477':'B4C4DBCE80C7ADCD2607D997E8EC2F838208B531EA196B7535A42A2FAD340510',
    '3994061529':'51EE32B610B7BA54D79557AC62F87FD1285BC65EB9694D82C54BCEF9BE80B08A',
    '3994062205':'2DDC71FE5729719AE223A862D16B8B17455B804639241B9832F7E904EC0F4FF8',
    '3994062444':'F21C2296F393E2437AE000213BEE4BE0B09F496A1C166F5B2E1BD45C91F41496',
    '3994062589':'D7FFF67C5C0D180DE45493A5EC9D52CF23C6E93DAEE0DC126056BB85C0191E12',
    '3994062676':'3920D6CA49DA0792B9EA6FAD9256150ACB77DBCC01E988A425C7D16BC6A25365',
    '3994062728':'EABE1BBB04404ADEF0DA553BBA2309A41AF303FC8E63270FFC7E40CD740E9B6F',
    '3994062769':'DD67AC6651EAD3B82B5C356330837CF24427543658573D5F6066A5BBEBE3B7F8',
    '3994062844':'A6F23C1518D151DD0B47E634F0E7010599EF14898CA18522C406A1288771809B',
    '3994062901':'2861F2CA8CFD94809DF65F1071A54341AB80A43B4DEFB752974285BF22D6F8C9',
    '3994063046':'C10AAA031A670BEF26F8F00EB7731CAA77EBD379608DF90C115DEB50CA4C59A3',
    '3994063108':'F01920296A3ADCE77653804A26445B91D42FF0AA1B451A2B06FD47847BA88388',
    '3994063151':'46275CE6A0EB5B6ECD8D1F3168EA3BEC37E7639B0BED8E8BB88FBE1AB55220B7',
    '3994063248':'FCFF00E138D9F0470804BF6B6982FE61473AF381943C1BFDF0B64B33C44BB9D7',
    '3994063284':'0D72E6F4BA44B431E342DB5C8229B88659DB0E3B1C1E577FD668A10A143F216A',
    '3994063315':'B09D07CB57F9D67F6829E95E14989F20EB896B7932E6158E26C5C1F0F0EFFDF2',
    '3994063347':'ECAB9C4EAEF6B0BB529F9F832701EE4AE586F923FEC263588C234091DE6CA98F',
    '3994063378':'968DF304BB00CED0C9A13C1CBAFD5D60A891583282D5293C37A11C803ADE934E',
    '3994063414':'E38DB9FD087E3F37A6B03A5B90801CB3241FDEDED3B212282BD177E615C24973',
    '3994063437':'D4467DD4776C463B79EB6FF3855F907D472BD632E350FA86E4AA47A32290E5ED',
    '3994063465':'C5998B96DF1B0A05AEF8A27136AF204846885D1DCCC4AA78D12DB8593270FA5E',
    '3994063526':'FC7A449247B0B305F19E04F5420E457F6051971A1ADC65A858CE935AA2392AD4',
    '3994063554':'6FA473A49784BE3FFB4B3FF1568AB8203620D30C5D422D21C5551C5AEEA012D9',
    '3994063575':'2B4150534BA84DA05D7C7CFECB25F15A36C268556DEE63D58C164633C557D83C',
    '3994063593':'2332FCD11A672DAA85C6BBB657C8AC90208FC83A92C2F436CCF2511CFCC3D5A2',
    '3994063620':'1E5285A880E1C9DA336531AB497D676414B53F27AA08BCEF44075485837861C8',
    '3994063813':'56916B0A0C7F9A1F5070D19F43A76A282561DFE0D132CC697204CCC94BEC8104',
    '3994063876':'30160AD8A87EE8509986916D2CE5EAA23F8140DA8774D9554DDB32A727DF5507',
    '3994063926':'33D2CB2D20DE41B44995E325564CC2BEE2F627AA94DDC42A3CBEC7A46B7234E2',
    '3994063973':'0E251138F64F83B3B4EEC11ED2416F7D0F4656673D6161354885F1F474151B69',
    '3994064010':'F899A7C7AB5E98A268E9605204CC8F7BD435584CF8E67293629EF6B62B26CC43',
    '3994064056':'6A850F655FAAB1456345DEA9F709D5C8CB10E8D6E28C8C0B53B0A51440190136',
    '3994064265':'38DE752A4D280FB09FE0EC4223C3A05A51E1FE2CAFAD95FFA70684383C74882D',
    '3994064289':'F59F67705D84480475FD2C706947EE9739001F12DA2AFC7CE9E6F10707B950D5',
    '3994064314':'AC5DF8E8EF266CF9D69E467361CB84126ED4B370DBA15CAB252A571633CBC515',
    '3994064356':'F35D8F6001B08650DB908C360108F73DB40B2E4489831250DD51E0B46315D42D',
    '3994064441':'F1ABEED6D9203191393B4DB41C45FF0319BAE9936F6E92825E9B0B4B4A85117F',
    '3994064465':'7E73BF7F1B1A6D91B93BD99DF67B179CDF696AA585DA69A4E8CA6B64E2A85310',
    '3994064507':'51D025592836FD042E8804505EB679AE9AEB57C1EC28107D9597A462FF0B1AF5',
    '3994064615':'4B0D3B87CC1E8DA8805F86E26BF77B18D103AD72CA804B4E20F92A11DEA896DD'
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