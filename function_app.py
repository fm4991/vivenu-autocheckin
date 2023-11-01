import logging
import azure.functions as func
import os
import requests

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="vivenuautocheckin")
def vivenuautocheckin(req: func.HttpRequest) -> func.HttpResponse:
    token = os.environ["VIVENU_TOKEN"]
    env = os.environ["VIVENU_ENV"]
    try:
        req_body = req.get_json()
    except ValueError: 
        pass 
    else: 
        try:
            ticket_barcode = req_body['data']['ticket']['barcode']
            ticket_origin = req_body['data']['ticket']['origin']
        except KeyError:
            pass
        else:
            if ticket_origin == "pos": 
                headers = {'token': f'{token}'}
                response = requests.post(f'https://{env}/api/accessusers/tickets/{ticket_barcode}/scan', headers=headers)
                return func.HttpResponse(f'StatusCode {response.status_code} and {response.text}', status_code=response.status_code)
            else: 
                return func.HttpResponse("No POS Ticket", status_code=200)