# hibpSearcher - A Have I Been Pwned searcher
# Author: alexos

import requests
import sys

# Use hibp.py <email file>
file = (sys.argv[1])

# Read email file 
with open(file, 'r') as s:
    email=s.read().splitlines()

api_key = "API_KEY" #Create your API Key in https://haveibeenpwned.com/API/Key

# Get name and dataclasses keys in the json file
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
