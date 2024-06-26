#!/usr/bin/env python3
# coding=utf-8

import _thread as thread

import traceback, signal, socket, sys, logging
from twisted.internet import reactor
from twisted.internet import task
import coloredlogs
coloredlogs.install(level='WARN')

sys.path.append("protocol")
sys.path.append(".")

from DataHandler import DataHandler
from Client import Client
from NATServer import NATServer

import ip2country # just to make sure it's downloaded
import ChanServ
import twistedserver

_root = DataHandler()
_root.parseArgv(sys.argv)

try:
	signal.SIGHUP

	def sighup(sig, frame):
		logging.info('Received SIGHUP.')
		if _root.sighup:
			_root.reload()

	signal.signal(signal.SIGHUP, sighup)
except AttributeError:
	pass

logging.info('Starting uberserver...')

try:
	natport = _root.natport
	natserver = NATServer(natport)
	thread.start_new_thread(natserver.start,())
	natserver.bind(_root)
except socket.error:
	logging.error("Could not start NAT server - hole punching will be unavailable.")

try:
	_root.init()
except:
	logging.error(traceback.format_exc())
	logging.info('Exception caught, exiting...')

try:
	reactor.listenTCP(_root.port, twistedserver.ChatFactory(_root))
	print('Started lobby server!')
	print('Connect the lobby client to')
	print('  public:  %s:%d' %(_root.online_ip, _root.port))
	print('  private: %s:%d' %(_root.local_ip, _root.port))
	
	clean_loop = task.LoopingCall(_root.scheduled_clean)
	clean_loop.start(60*60*24)
	
	event_loop = task.LoopingCall(_root.channel_mute_ban_timeout)
	event_loop.start(1)
	recent_registration_loop = task.LoopingCall(_root.decrement_recent_registrations)
	recent_registration_loop.start(60*20)
	recent_rename_loop = task.LoopingCall(_root.decrement_recent_renames)
	recent_rename_loop.start(60*60*24*7)
	
	reactor.run()

except KeyboardInterrupt:
	logging.info()
	logging.info('Server killed by keyboard interrupt.')
except:
	logging.error(traceback.format_exc())
	logging.info('Exception caught, exiting...')

_root.shutdown()

