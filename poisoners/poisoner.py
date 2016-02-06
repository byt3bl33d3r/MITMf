import threading

class Poisoner(object):
	name = 'Example Poisoner'
	optname = 'arp'

	def poison(self):
		pass

	def start(self):
		t = threading.Thread(name=self.name, target=self.poison, args=())
		t.setDaemon(True)
		t.start()