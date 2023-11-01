import azure.functions as func
import logging, os, requests, hmac, hashlib

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

def ct_compare(a, b):
	if len(a) != len(b):
		return False
	result = 0
	for ch_a, ch_b in zip(a, b):
		result |= ord(ch_a) ^ ord(ch_b)
	return result == 0

def verifySignature(string_to_verify, signature, shared_secret):
	return ct_compare(hmac.new(shared_secret, 
		string_to_verify, hashlib.md5).digest(), signature)


@app.route(route="vivenuautocheckin")
def vivenuautocheckin(req: func.HttpRequest) -> func.HttpResponse:
    token = os.environ["VIVENU_TOKEN"]
    env = os.environ["VIVENU_ENV"]
    hmac_key = os.environ["VIVENU_HMACKEY"]
    try:
        req_body = req.get_json()
        hmac_hash = req.headers['x-vivenu-signature']    
    except ValueError: 
        return func.HttpResponse("Error parsing Webhook Data (JSON)", status_code=400)
    except KeyError:
        return func.HttpResponse("Error parsing Webhook Data (HMAC)", status_code=400)
    else:
        try:
            if verifySignature(req_body, hmac_hash, hmac_key) is False:
                return func.HttpResponse("401 Unauthorized", status_code=401)
        except:
            return func.HttpResponse("401 Unauthorized!", status_code=401)
        else:
            try:
                ticket_barcode = req_body['data']['ticket']['barcode']
                ticket_origin = req_body['data']['ticket']['origin']
            except KeyError:
                return func.HttpResponse("Expected Keys not found in Webhook Data, Probably not a POS Ticket", status_code=200)
            else:
                if ticket_origin == "pos": 
                    headers = {'token': f'{token}'}
                    response = requests.post(f'https://{env}/api/accessusers/tickets/{ticket_barcode}/scan', headers=headers)
                    return func.HttpResponse(f'StatusCode {response.status_code} and {response.text}', status_code=response.status_code)
                else: 
                    return func.HttpResponse("No POS Ticket", status_code=200)