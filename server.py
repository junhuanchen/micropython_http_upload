
# coding=utf-8
from http.server import BaseHTTPRequestHandler
import cgi
import time


class PostHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        print({'REQUEST_METHOD': 'POST',
                     'CONTENT_TYPE': self.headers['Content-Type'],
                     })
        print(self.headers)
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST',
                     'CONTENT_TYPE': self.headers['Content-Type'],
                     }
        )
        self.send_response(200)
        self.end_headers()
        self.wfile.write(('Client: %s\n' % str(self.client_address)).encode())
        self.wfile.write(('User-agent: %s\n' %
                          str(self.headers['user-agent'])).encode())
        self.wfile.write(('Path: %s\n' % self.path).encode())
        self.wfile.write(b'Form data:\n')
        print(form.keys())
        for field in form.keys():
            field_item = form[field]
            filename = field_item.filename
            filevalue = field_item.value
            filesize = len(filevalue)  # 文件大小(字节)
            print(filename, filesize)
            with open('%s-' % time.time() + filename, 'wb') as f:
                f.write(filevalue)
        return


def StartServer():
    from http.server import HTTPServer
    sever = HTTPServer(("0.0.0.0", 8080), PostHandler)
    sever.serve_forever()


if __name__ == '__main__':
    StartServer()
