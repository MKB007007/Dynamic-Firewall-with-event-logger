from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler


class Server(ThreadingHTTPServer):
    request_queue_size = 512     # default is 5, which drops SYNs under load
    daemon_threads = True


Server(("0.0.0.0", 9000), SimpleHTTPRequestHandler).serve_forever()
