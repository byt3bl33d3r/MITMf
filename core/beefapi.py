#! /usr/bin/env python2.7

# BeEF-API - A Python API for BeEF (The Browser Exploitation Framework) http://beefproject.com/ 

# Copyright (c) 2015-2016 Marcello Salvati - byt3bl33d3r@gmail.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

import requests
import json

from UserList import UserList

class BeefAPI:

    def __init__(self, opts=[]):
        self.host = opts.get('host') or "127.0.0.1"
        self.port = opts.get('port') or "3000"
        self.token = None
        self.url = "http://{}:{}/api/".format(self.host, self.port)
        self.login_url = self.url + "admin/login"

    def login(self, username, password):
        try:
            auth = json.dumps({"username": username, "password": password})
            r = requests.post(self.login_url, data=auth)
            data = r.json()

            if (r.status_code == 200) and (data["success"]):
                self.token = data["token"]  #Auth token

                self.hooks_url   = "{}hooks?token={}".format(self.url, self.token)
                self.modules_url = "{}modules?token={}".format(self.url, self.token)
                self.logs_url    = "{}logs?token={}".format(self.url, self.token)
                self.are_url     = "{}autorun/rule/".format(self.url)
                self.dns_url     = "{}dns/ruleset?token={}".format(self.url, self.token)

                return True
            elif r.status_code != 200:
                return False

        except Exception as e:
            print "[BeEF-API] Error logging in to BeEF: {}".format(e)

    @property   
    def hooked_browsers(self):
        r = requests.get(self.hooks_url)
        return Hooked_Browsers(r.json(), self.url, self.token)

    @property
    def dns(self):
        r = requests.get(self.dns_url)
        return DNS(r.json(), self.url, self.token)

    @property
    def logs(self):
        logs = []
        r = requests.get(self.logs_url)
        for log in r.json()['logs']:
            logs.append(Log(log))
        return logs

    @property
    def modules(self):
        modules = ModuleList([])
        r = requests.get(self.modules_url)
        for k,v in r.json().iteritems():
            modules.append(Module(v, self.url, self.token))
        return modules

    @property
    def are_rules(self):
        return ARE_Rules(self.are_url, self.token)

class ModuleList(UserList):

    def __init__(self, mlist):
        self.data = mlist

    def findbyid(self, m_id):
        for m in self.data:
            if m_id == m.id:
                return m

    def findbyname(self, m_name):
        pmodules = ModuleList([])
        for m in self.data:
            if (m.name.lower().find(m_name.lower()) != -1) :
                pmodules.append(m)
        return pmodules

class SessionList(UserList):

    def __init__(self, slist):
        self.data = slist

    def findbysession(self, session):
        for s in self.data:
            if s.session == session:
                return s

    def findbyos(self, os):
        res = SessionList([])
        for s in self.data:
            if (s.os.lower().find(os.lower()) != -1):
                res.append(s)
        return res

    def findbyip(self, ip):
        res = SessionList([])
        for s in self.data:
            if ip == s.ip:
                res.append(s)
        return res

    def findbyid(self, s_id):
        for s in self.data:
            if s.id == s_id:
                return s

    def findbybrowser(self, browser):
        res = SessionList([])
        for s in self.data:
            if browser == s.name:
                res.append(s)
        return res

    def findbybrowser_v(self, browser_v):
        res = SessionList([])
        for s in self.data:
            if browser_v == s.version:
                res.append(s)
        return res

    def findbypageuri(self, uri):
        res = SessionList([])
        for s in self.data:
            if uri in s.page_uri:
                res.append(s)
        return res

    def findbydomain(self, domain):
        res = SessionList([])
        for s in self.data:
            if domain in s.domain:
                res.append(s)
        return res

class ARE_Rule(object):

    def __init__(self, data, url, token):
        self.url = url
        self.token = token

        for k,v in data.iteritems():
            setattr(self, k, v)

        self.modules = json.loads(self.modules)

    def trigger(self):
        r = requests.get('{}/trigger/{}?token={}'.format(self.url, self.id, self.token))
        return r.json()

    def delete(self):
        r = requests.get('{}/delete/{}?token={}'.format(self.url, self.id, self.token))
        return r.json()

class ARE_Rules(object):

    def __init__(self, url, token):
        self.url = url
        self.token = token

    def list(self):
        rules = []
        r = requests.get('{}/list/all?token={}'.format(self.url, self.token))
        data = r.json()
        if (r.status_code == 200) and (data['success']):
            for rule in data['rules']:
                rules.append(ARE_Rule(rule, self.url, self.token))

            return rules

    def add(self, rule_path):
        if rule_path.endswith('.json'):
            headers = {'Content-Type': 'application/json; charset=UTF-8'}
            with open(rule_path, 'r') as rule:
                payload = rule.read()
                r = requests.post('{}/add?token={}'.format(self.url, self.token), data=payload, headers=headers)
            return r.json()

    def trigger(self, rule_id):
        r = requests.get('{}/trigger/{}?token={}'.format(self.url, rule_id, self.token))
        return r.json()

    def delete(self, rule_id):
        r = requests.get('{}/delete/{}?token={}'.format(self.url, rule_id, self.token))
        return r.json()

class Module(object):

    def __init__(self, data, url, token):
        self.url = url
        self.token = token

        for k,v in data.iteritems():
            setattr(self, k, v)

    @property
    def options(self):
        r = requests.get("{}/modules/{}?token={}".format(self.url, self.id, self.token)).json()
        return r['options']

    @property
    def description(self):
        r = requests.get("{}/modules/{}?token={}".format(self.url, self.id, self.token)).json()
        return r['description']

    def run(self, session, options={}):
        headers = {"Content-Type": "application/json", "charset": "UTF-8"}
        payload = json.dumps(options)
        r = requests.post("{}/modules/{}/{}?token={}".format(self.url, session, self.id, self.token), headers=headers, data=payload)
        return r.json()

    def multi_run(self, options={}, hb_ids=[]):
        headers = {"Content-Type": "application/json", "charset": "UTF-8"}
        payload = json.dumps({"mod_id":self.id, "mod_params": options, "hb_ids": hb_ids})
        r = requests.post("{}/modules/multi_browser?token={}".format(self.url, self.token), headers=headers, data=payload)
        return r.json()

    def results(self, session, cmd_id):
        r = requests.get("{}/modules/{}/{}/{}?token={}".format(self.url, session, self.id, cmd_id, self.token))
        return r.json()

class Log(object):

    def __init__(self, log_dict):
        for k,v in log_dict.iteritems():
            setattr(self, k, v)

class DNS_Rule(object):

    def __init__(self, rule, url, token):
        self.url = url
        self.token = token

        for k,v in rule.iteritems():
            setattr(self, k, v)

    def delete(self):
        r = requests.delete("{}/dns/rule/{}?token={}".format(self.url, self.id, self.token))
        return r.json()

class DNS(object):

    def __init__(self, data, url, token):
        self.data = data
        self.url = url
        self.token = token

    @property
    def ruleset(self):
        ruleset = []
        r = requests.get("{}/dns/ruleset?token={}".format(self.url, self.token))
        for rule in r.json()['ruleset']:
            ruleset.append(DNS_Rule(rule, self.url, self.token))
        return ruleset

    def add(self, pattern, resource, response=[]):
        headers = {"Content-Type": "application/json", "charset": "UTF-8"}
        payload = json.dumps({"pattern": pattern, "resource": resource, "response": response})
        r = requests.post("{}/dns/rule?token={}".format(self.url, self.token), headers=headers, data=payload)
        return r.json()

    def delete(self, rule_id):
        r = requests.delete("{}/dns/rule/{}?token={}".format(self.url, rule_id, self.token))
        return r.json()

class Hooked_Browsers(object):

    def __init__(self, data, url, token):
        self.data = data
        self.url = url
        self.token = token

    @property
    def online(self):
        sessions = SessionList([])
        for k,v in self.data['hooked-browsers']['online'].iteritems():
            sessions.append(Session(v['session'], self.data, self.url, self.token))
        return sessions

    @property
    def offline(self):
        sessions = SessionList([])
        for k,v in self.data['hooked-browsers']['offline'].iteritems():
            sessions.append(Session(v['session'], self.data, self.url, self.token))
        return sessions

class Session(object):

    def __init__(self, session, data, url, token):
        self.session = session
        self.data = data
        self.url = url
        self.token = token

        self.domain = self.get_property('domain')
        self.id = self.get_property('id')
        self.ip = self.get_property('ip')
        self.name = self.get_property('name') #Browser name
        self.os = self.get_property('os')
        self.page_uri = self.get_property('page_uri')
        self.platform = self.get_property('platform') #Ex. win32
        self.port = self.get_property('port')
        self.version = self.get_property('version') #Browser version

    @property
    def details(self):
        r = requests.get('{}/hooks/{}?token={}'.format(self.url, self.session, self.token))
        return r.json()

    @property
    def logs(self):
        logs = []
        r = requests.get('{}/logs/{}?token={}'.format(self.url, self.session, self.token))
        for log in r.json()['logs']:
            logs.append(Log(log))
        return logs

    def update(self, options={}):
        headers = {"Content-Type": "application/json", "charset": "UTF-8"}
        payload = json.dumps(options)
        r = requests.post("{}/hooks/update/{}?token={}".format(self.url, self.session, self.token), headers=headers, data=payload)
        return r.json()

    def run(self, module_id, options={}):
        headers = {"Content-Type": "application/json", "charset": "UTF-8"}
        payload = json.dumps(options)
        r = requests.post("{}/modules/{}/{}?token={}".format(self.url, self.session, module_id, self.token), headers=headers, data=payload)
        return r.json()

    def multi_run(self, options={}):
        headers = {"Content-Type": "application/json", "charset": "UTF-8"}
        payload = json.dumps({"hb": self.session, "modules":[options]})
        r = requests.post("{}/modules/multi_module?token={}".format(self.url, self.token), headers=headers, data=payload)
        return r.json()

    def get_property(self, key):
        for k,v in self.data['hooked-browsers'].iteritems():
            for l,s in v.iteritems(): 
                if self.session == s['session']:
                    return s[key]
