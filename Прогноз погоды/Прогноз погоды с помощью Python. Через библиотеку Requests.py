import requests

r = requests.get('https://wttr.in/�����?0&lang=ru')
print(r.text)