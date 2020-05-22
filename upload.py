#coding=utf-8
import requests
url = "http://127.0.0.1:8080"
path = "./hfshttp.zip"
print(path)
files = {'file': open(path, 'rb')}
r = requests.post(url, files=files)
print (r.url)
print (r.text)

'''
Host: 127.0.0.1:8080
Connection: keep-alive
Accept: */*
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Content-Length: 859783
Content-Type: multipart/form-data; boundary=c42a6d00053f74d5edd8c8b00a8318ef
['file']
hfshttp.zip 859636
'''
