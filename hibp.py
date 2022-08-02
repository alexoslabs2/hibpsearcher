import requests
import sys

file = (sys.argv[1])

with open(file, 'r') as s:
    email=s.read().splitlines()

api_key = "021b8085db734d848068b5dde2454c80"

for line in email:
    print(line)
    url = 'https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false'.format(line)
    headers = {'hibp-api-key': str(api_key)} 
    request = requests.get(url, headers=headers)
    status = request.status_code
    if status == 200:
        name = request.json()[0]['Name']
        dataclasse = request.json()[0]['DataClasses']
        print(name,dataclasse)