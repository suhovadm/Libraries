import requests

r = requests.get('https://wttr.in/Пермь?0&lang=ru')
print(r.text)