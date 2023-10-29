import logging
import azure.functions as func
import os
import requests

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="vivenuautocheckin")
def vivenuautocheckin(req: func.HttpRequest) -> func.HttpResponse:
    authorization = os.environ["VIVENU_AUTH"]
    categoryRef = os.environ["VIVENU_CATEGORYREF"]
    try:
        req_body = req.get_json() 
    except ValueError: 
        pass 
    else: 
        ticket_categoryRef = req_body['data']['ticket']['categoryRef']
        ticket_barcode = req_body['data']['ticket']['barcode']

    if ticket_categoryRef == categoryRef: 
        response = requests.post(f'https://vivenu.com//api/accessusers/tickets/{ticket_barcode}/scan', headers=f'{"Authorization": "{authorization}"}')
        return func.HttpResponse(response) 
    else: 
        return func.HttpResponse( 
            "keine Abendkasse", 
            status_code=200 
        )