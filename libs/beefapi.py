#!/usr/bin/env python
import requests
import json
from random import sample
from string import lowercase, digits


class BeefAPI:

	def __init__(self, opts=[]):
		self.host = "127.0.0.1" or opts.get(host)
		self.port = "3000" or opts.get(port)
		self.token = None
		self.url = "http://%s:%s/api/" % (self.host, self.port)
		self.login_url = self.url + "admin/login"
		self.hookurl = self.url + "hooks?token="
		self.mod_url = self.url + "modules?token="
		self.log_url = self.url + "logs?token="

	def random_url(self):
		return "".join(sample(digits + lowercase, 8))

	def login(self, username, password):
		try:
			auth = json.dumps({"username": username, "password": password})
			r = requests.post(self.login_url, data=auth)
			data = r.json()

			if (r.status_code == 200) and (data["success"]):
				self.token = data["token"]  #Auth token
				return True
			elif r.status_code != 200:
				return False

		except Exception, e:
			print "beefapi ERROR: %s" % e

	def sessions_online(self):
		return self.get_sessions("online", "session")

	def sessions_offline(self):
		return self.get_sessions("offline", "session")

	def session2host(self, session):
		return self.conversion(session, "ip")

	def session2id(self, session):
		return self.conversion(session, "id")

	def hook_info(self, hook):  #Returns parsed information on a session
		session = self.conversion(hook, "session")
		url = self.hookurl + self.token
		r = requests.get(url).json()

		try:
			states = ["online", "offline"]
			for state in states:
				for v in r["hooked-browsers"][state].items():
					if v[1]["session"] == session:
						return v[1]
		except IndexError:
			pass

	def hook_info_all(self, hook):
		session = self.conversion(hook, "session")
		url = self.url + "hooks/%s?token=%s" % (session, self.token)
		return requests.get(url).json()

	def hook_logs(self, hook):
		session = self.conversion(hook, "session")
		url = self.url + "logs/%s?token=%s" % (session, self.token)
		return requests.get(url).json()

	def hosts_online(self):
		return self.get_sessions("online", "ip")

	def hosts_offline(self):
		return self.get_sessions("offline", "ip")

	def host2session(self, host):
		return self.conversion(host, "session")

	def host2id(self, host):
		return self.conversion(host, "id")

	def ids_online(self):
		return self.get_sessions("online", "id")

	def ids_offline(self):
		return self.get_sessions("offline", "id")

	def id2session(self, id):
		return self.conversion(id, "session")

	def id2host(self, id):
		return self.conversion(id, "ip")

	def module_id(self, name):  #Returns module id
		url = self.mod_url + self.token
		try:
			r = requests.get(url).json()
			for v in r.values():
				if v["name"] == name:
					return v["id"]
		except Exception, e:
			print "beefapi ERROR: %s" % e

	def module_name(self, id):  #Returns module name
		url = self.mod_url + self.token
		try:
			r = requests.get(url).json()
			for v in r.values():
				if v["id"] == id:
					return v["name"]
		except Exception, e:
			print "beefapi ERROR: %s" % e

	def module_run(self, hook, mod_id, options={}):  #Executes a module on a specified session
		try:
			session = self.conversion(hook, "session")
			headers = {"Content-Type": "application/json", "charset": "UTF-8"}
			payload = json.dumps(options)
			url = self.url + "modules/%s/%s?token=%s" % (session, mod_id, self.token)
			return requests.post(url, headers=headers, data=payload).json()
		except Exception, e:
			print "beefapi ERROR: %s" % e

	def module_results(self, hook, mod_id, cmd_id):
		session = self.conversion(hook, "session")
		url = self.mod_url + "%s/%s/%s?token=%s" % (session, mod_id, cmd_id, self.token)
		return requests.get(url).json()

	def modules_list(self):
		return requests.get(self.mod_url + self.token).json()

	def module_info(self, id):
		url = self.url + "modules/%s?token=%s" % (id, self.token)
		return requests.get(url).json()

	def logs(self):
		return requests.get(self.log_url + self.token).json()

	def conversion(self, value, return_value):  #Helper function for all conversion functions 
		url = self.hookurl + self.token
		try:
			r = requests.get(url).json()
			states = ["online", "offline"]
			for state in states:
				for v in r["hooked-browsers"][state].items():
					for r in v[1].values():
						if str(value) == str(r):
							return v[1][return_value]

		except Exception, e:
			print "beefapi ERROR: %s" % e

		except IndexError:
			pass

	def get_sessions(self, state, value):  #Helper function
		try:
			hooks = []
			r = requests.get(self.hookurl + self.token).json()
			for v in r["hooked-browsers"][state].items():
				hooks.append(v[1][value])

			return hooks
		except Exception, e:
			print "beefapi ERROR: %s" % e
