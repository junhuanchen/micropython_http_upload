
"""
The MIT License (MIT)
Copyright © 2019    junhuanchen@qq.com

mini requests.

"""

class MiniHttp:

  def readline(self):
    return self.raw.readline() # mpy

  def write(self, data):
    return self.raw.write(data) # mpy

  def read(self, len):
    return self.raw.read(len) # mpy

  table = {
    0x2B:b'%2B',
    0x20:b'%20',
    0x2F:b'%2F',
    0x3F:b'%3F',
    0x25:b'%25',
    0x23:b'%23',
    0x26:b'%26',
    0x3D:b'%3D',
  }

  def base2url(self, data):
    result = b''
    for i in range(len(data)):
      result += __class__.table[data[i]] if data[i] in __class__.table else data[i:i+1]
    return result

  def __init__(self):
    self.raw = None

  def connect(self, url, timeout=2):
    try:
      proto, dummy, host, path = url.split("/", 3)
    except ValueError:
      proto, dummy, host = url.split("/", 2)
      path = ""

    if proto == "http:":
      port = 80
    elif proto == "https:":
      port = 443
    else:
      raise ValueError("Unsupported protocol: " + proto)

    if ":" in host:
      host, port = host.split(":", 1)
      port = int(port)

    import socket
    ai = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    ai = ai[0]
    if self.raw is not None:
      self.raw.close()
    raw = socket.socket(ai[0], ai[1], ai[2])
    raw.settimeout(timeout)

    raw.connect(ai[-1])
    if proto == "https:":
      import ussl
      # raw = ssl.wrap_socket(raw, server_hostname=host)
      raw = ussl.wrap_socket(raw)
    self.raw = raw
    self.host = bytes(host, "utf-8")
    self.path = bytes(path, "utf-8")

  def exit(self):
    if self.raw != None:
      self.raw.close()
      self.raw = None

  def request(self, method, headers = {}, data=None):
    try:
      self.headers = headers
      self.write(b"%s /%s HTTP/1.1\r\n" % (method, self.path))
      if not "Host" in headers:
        self.write(b"Host: %s\r\n" % self.host)
      # Iterate over keys to avoid tuple alloc
      for k in headers:
        self.write(k)
        self.write(b": ")
        self.write(headers[k])
        self.write(b"\r\n")
      if data:
        self.write(b"Content-Length: %d\r\n" % len(data))
      self.write(b"\r\n")
      if data:
        self.write(data)
      l = self.readline()
      l = l.split(None, 2)
      status = int(l[1])
      reason = ""
      response = {}
      if len(l) > 2:
        reason = l[2].rstrip()
      while True:
        l = self.readline()
        if not l or l == b"\r\n":
          break
        if l.startswith(b"Transfer-Encoding:"):
          if b"chunked" in l:
            raise ValueError("Unsupported " + l)
        elif l.startswith(b"Location:") and not 200 <= status <= 299:
          raise NotImplementedError("Redirects not yet supported")
        try:
          tmp = l.split(b': ')
          response[tmp[0]] = tmp[1][:-2]
        except Exception as e:
          print(e)
    except OSError:
      self.exit()
      raise
    print(response)
    return (status, reason, response)


if __name__ == "__main__":
  import time
  start = time.time()
  print('start', start)
  try:
    url = 'https://aip.baidubce.com/rest/2.0/image-classify/v1/gesture?access_token=24.334eff1a7837acd251ef7001abf1288e.2592000.1605331663.282335-15994053'
    tmp = MiniHttp()
    head = {
      b'Connection' : b'keep-alive',
      b'Content-Type' : b'application/x-www-form-urlencoded',
      b'Accept' : b'*/*',
      b'Cache-Control' : b'no-cache',
    }
    while True:
      try:
        #time.sleep(1)
        if tmp.raw is None:
          tmp.connect(url, 2)
        else:
          img = b''
          with open("ok.txt", 'rb') as f:
            img = f.read()
          res = tmp.request(b"POST", head, b"image=" + tmp.base2url(img))
          print(res[0], res[1])
          data = tmp.read(int(res[2][b'Content-Length'], 10))
          print(len(data), str(data, 'utf-8'))
          import json
          result = json.loads(str(data, 'utf-8'))
          print(result)
      except Exception as e:
        print(e)
        raise e
  finally:
    tmp.exit()
