import hmac, hashlib
signature='3a2dcfdc259d01b153775d6d9e7a2c7567bdfe829467fe096ebc25cfa417dbb4'
key='af871ed7-48ef-437d-b9ea-d4ee5848e7e6'
text='{"id":"eec0577d-bd2d-417b-8d28-442d3d9fab39","sellerId":"6461d48a6d6734e7b0d35334","webhookId":"6542b60805855ccb0cb203f2","type":"ticket.created","mode":"dev","data":{"ticket":{"__v":1,"_id":"6542b80605855ccb0cb20fee","barcode":"0lvgest4lw","cartItemId":"0761bc98-7247-45e7-96b4-2b35b6d61c3b","categoryRef":"b4b5d742-c805-4f62-bea1-9e4982273661","createdAt":"2023-11-01T20:41:42.103Z","currency":"EUR","deliveryType":"VIRTUAL","entryPermissions":[],"eventId":"646768a72af1b1bab37e6428","excludedEventIds":[],"expired":false,"history":[{"_id":"6542b80605855ccb0cb20fef","date":"2023-11-01T20:41:42.100Z","type":"ticket.created"},{"_id":"6542b80605855ccb0cb20ff8","date":"2023-11-01T20:41:42.969Z","type":"ticket.validated"}],"name":"","origin":"pos","personalized":false,"posId":"6461d5302af1b1bab36b3dc6","realPrice":10,"regularPrice":10,"secret":"4b5bd382-e909-47ef-9157-689ee0cf6de2","sellerId":"6461d48a6d6734e7b0d35334","status":"VALID","ticketName":"Ticket","ticketTypeId":"646768b1287b25b90d73bfc7","transactionId":"6542b80605855ccb0cb20fe2","triggeredBy":[],"type":"SINGLE","updatedAt":"2023-11-01T20:41:42.971Z"}}}'

def verifySignature(string_to_verify, signature, shared_secret):
    digest_maker = hmac.new(shared_secret.encode(),''.encode(),hashlib.sha256)
    digest_maker.update(string_to_verify.encode())
    digest =digest_maker.hexdigest()
    if len(digest) != len(signature):
        return False
    elif digest == signature:
        return True
    else:
        return False

print(verifySignature(text, signature, key))


pass