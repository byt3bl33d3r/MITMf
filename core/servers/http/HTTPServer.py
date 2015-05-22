import tornado.ioloop
import tornado.web
import threading

class HTTPServer:

    _instance = None
    application = tornado.web.Application([])

    @staticmethod
    def getInstance():
        if HTTPServer._instance == None:
            HTTPServer._instance = HTTPServer()

        return HTTPServer._instance

    def addHandler(self, urlregex, handler, vhost=''):
        self.application.add_handlers(vhost, [(urlregex, handler)])

    def start(self, port=80):
        self.application.listen(port)
        t = threading.Thread(name='HTTPserver', target=tornado.ioloop.IOLoop.instance().start)
        t.setDaemon(True)
        t.start()
