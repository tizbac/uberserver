import thread, time, sys, os, socket

import base64
try: from hashlib import md5
except: md5 = __import__('md5').new

import traceback
from protocol.Channel import Channel
from protocol.Protocol import Protocol
from SQLUsers import UsersHandler, ChannelsHandler
import ip2country
import datetime

separator = '-'*60

class DataHandler:

	def __init__(self):
		self.local_ip = None
		self.online_ip = None
		self.session_id = 0
		self.dispatcher = None
		self.console_buffer = []
		self.port = 8200
		self.natport = self.port+1
		self.latestspringversion = '*'
		self.log = False
		self.logfile = None
		self.logfilename = 'server.log'
		self.agreementfile = 'agreement.rtf'
		self.agreement = []
		self.server = 'TASServer'
		self.server_version = 0.36
		self.sighup = False
		
		self.chanserv = None
		self.userdb = None
		self.channeldb = None
		self.engine = None
		self.protocol = None
		self.updatefile = None
		self.trusted_proxyfile = None
		
		self.max_threads = 25
		self.sqlurl = 'sqlite:///server.db'
		self.nextbattle = 0
		self.SayHooks = __import__('SayHooks')
		self.censor = True
		self.motd = None
		self.running = True
		
		self.trusted_proxies = []
		
		self.start_time = time.time()
		self.channels = {}
		self.chan_alias = {}
		self.usernames = {}
		self.clients = {}
		self.db_ids = {}
		self.battles = {}
		thread.start_new_thread(self.event_loop, ())

	def showhelp(self):
		print 'Usage: server.py [OPTIONS]...'
		print 'Starts uberserver.'
		print
		print 'Options:'
		print '  -h, --help'
		print '      { Displays this screen then exits }'
		print '  -p, --port number'
		print '      { Server will host on this port (default is 8200) }'
		print '  -n, --natport number'
		print '      { Server will use this port for NAT transversal (default is 8201) }'
		print '  -g, --loadargs filename'
		print '      { Reads additional command-line arguments from file }'
		print '  -o, --output /path/to/file.log'
		print '      { Writes console output to file (for logging) }'
		print '  -u, --sighup'
		print '      { Reload the server on SIGHUP (if SIGHUP is supported by OS) }'
		print '  -v, --latestspringversion version'
		print '      { Sets latest Spring version to this string. Defaults to "*" }'
		print '  -m, --maxthreads number'
		print '      { Uses the specified number of threads for handling clients }'
		print '  -s, --sqlurl SQLURL'
		print '      { Uses SQL database at the specified sqlurl for user, channel, and ban storage. }'
		print '  -c, --no-censor'
		print '      { Disables censoring of #main, #newbies, and usernames (default is to censor) }'
		print '  --proxies /path/to/proxies.txt'
		print '     { Path to proxies.txt, for trusting proxies to pass real IP through local IP }'
		print '   -a --agreement /path/to/agreement.rtf'
		print '     { sets the pat to the agreement file which is sent to a client registering at the server }'
		print 'SQLURL Examples:'
		#print '  "sqlite:///:memory:" or "sqlite:///"'
		#print '     { both make a temporary database in memory }'
		print '  "sqlite:////absolute/path/to/database.txt"'
		print '     { uses a database in the file specified }'
		print '  "sqlite:///relative/path/to/database.txt"'
		print '     { note sqlite is slower than a real SQL server }'
		print '  "mysql://user:password@server:port/database"'
		print '     { requires the MySQLdb module }'
		print '  "oracle://user:password@server:port/database"'
		print '     { requires the cx_Oracle module }'
		print '  "postgres://user:password@server:port/database"'
		print '     { requires the psycopg2 module }'
		print '  "mssql://user:password@server:port/database"'
		print '     { requires pyodbc (recommended) or adodbapi or pymssql }'
		print '  "firebird://user:password@server:port/database"'
		print '     { requires the kinterbasdb module }'
		print
		print 'Usage example (this is what the test server uses at the moment):'
		print ' server.py -p 8300 -n 8301'
		print
		exit()
	def parseArgv(self, argv):
		'parses command-line options'
		args = {'ignoreme':[]}
		mainarg = 'ignoreme'

		tempargv = list(argv)
		while tempargv:
			arg = tempargv.pop(0)
			if arg.startswith('-'):
				mainarg = arg.lstrip('-').lower()

				if mainarg in ['g', 'loadargs']:
					try:
						name = tempargv[0]
						if name.startswith('-'): raise Exception
						f = file(name, 'r')
						lines = f.read().split('\n')
						f.close()

						tempargv += ' '.join(lines).split(' ')
					except:
						pass

				args[mainarg] = []
			else:
				args[mainarg].append(arg)
		del args['ignoreme']

		for arg in args:
			argp = args[arg]
			if arg in ['h', 'help']:
				self.showhelp()
			if arg in ['p', 'port']:
				try: self.port = int(argp[0])
				except: print 'Invalid port specification'
			elif arg in ['n', 'natport']:
				try: self.natport = int(argp[0])
				except: print 'Invalid NAT port specification'
			elif arg in ['o', 'output']:
				try: self.logfilename = argp[0]
				except: print 'Error specifying log location'
				self.rotatelogfile()
			elif arg in ['u', 'sighup']:
				self.sighup = True
			elif arg in ['v', 'latestspringversion']:
				try: self.latestspringversion = argp[0] # ' '.join(argp) # shouldn't have spaces
				except: print 'Error specifying latest spring version'
			elif arg in ['m', 'maxthreads']:
				try: self.max_threads = int(argp[0])
				except: print 'Error specifing max threads'
			elif arg in ['s', 'sqlurl']:
				try:
					self.sqlurl = argp[0]
				except:
					print 'Error specifying SQL URL'
			elif arg in ['c', 'no-censor']:
				self.censor = False
			elif arg in ['a', 'agreement']:
				try:
					self.argeementfile = argp[0]
				except:
					print 'Error reading agreement file'
			elif arg == 'proxies':
				try:
					self.trusted_proxyfile = argp[0]
					open(self.trusted_proxyfile, 'r').close()
				except:
					print 'Error opening trusted proxy file.'
					self.trusted_proxyfile = None
		sqlalchemy = __import__('sqlalchemy')
		if self.sqlurl.startswith('sqlite'):
			print 'Multiple threads are not supported with sqlite, forcing a single thread'
			print 'Please note the server performance will not be optimal'
			print 'You might want to install a real database server or use LAN mode'
			print
			self.max_threads = 1
			self.engine = sqlalchemy.create_engine(self.sqlurl)
			def _fk_pragma_on_connect(dbapi_con, con_record):
				dbapi_con.execute('PRAGMA journal_mode = MEMORY')
				dbapi_con.execute('PRAGMA synchronous = OFF')
			from sqlalchemy import event
			event.listen(self.engine, 'connect', _fk_pragma_on_connect)
		else:
			self.engine = sqlalchemy.create_engine(self.sqlurl, pool_size=self.max_threads * 2, pool_recycle=300)

		self.userdb = UsersHandler(self, self.engine)
		self.channeldb = ChannelsHandler(self, self.engine)
		channels = self.channeldb.load_channels()
		
		for name in channels:
			channel = channels[name]
			
			owner = None
			admins = []
			client = self.userdb.clientFromUsername(channel['owner'])
			if client and client.id: owner = client.id
				
			for user in channel['admins']:
				client = userdb.clientFromUsername(user)
				if client and client.id:
					admins.append(client.id)
				
			self.channels[name] = Channel(self, name, chanserv=bool(owner), owner=owner, admins=admins, key=channel['key'], antispam=channel['antispam'], topic={'user':'ChanServ', 'text':channel['topic'], 'time':int(time.time())})
			
		if self.chanserv:
			for name in channels:
				self.chanserv.client._protocol._handle(self.chanserv.client, 'JOIN %s' % name)
		
		if not self.log:
			self.rotatelogfile()
		
		self.parseFiles()

		self.protocol = Protocol(self)
	
	def parseFiles(self):
		if os.path.isfile('motd.txt'):
			motd = []
			f = open('motd.txt', 'r')
			data = f.read()
			f.close()
			if data:
				for line in data.split('\n'):
					motd.append(line.strip())
			self.motd = motd
		
		if self.trusted_proxyfile:
			self.trusted_proxies = set([])
			f = open(self.trusted_proxyfile, 'r')
			data = f.read()
			f.close()
			if data:
				for line in data.split('\n'):
					proxy = line.strip()
					if not proxy.replace('.', '', 3).isdigit():
						proxy = socket.gethostbyname(proxy)
					
					if proxy:
						self.trusted_proxies.add(proxy)
		ins = open(self.agreementfile, "r" )
		for line in ins:
			self.agreement.append(line.rstrip('\r\n'))
		ins.close()

	def getUserDB(self):
		return self.userdb
	
	def clientFromID(self, db_id):
		if db_id in self.db_ids: return self.db_ids[db_id]
	
	def clientFromUsername(self, username):
		if username in self.usernames: return self.usernames[username]

	def event_loop(self):
		start = time.time()
		lastsave = lastmute = lastidle = lastload = start
		load = 0
		try:
			os.getloadavg()
			hasload = True
		except:
			hasload = False
		while self.running:
			now = time.time()
			if hasload and now - lastload > 1: # only fetch load when available & last fetch was >1 sec ago
				lastload = now
				load, _, _ = os.getloadavg()
			try:
				if load > 8: # if load is higher than this, skip some steps
					pass
				elif now - lastmute >= 1:
					lastmute = now
					self.mute_timeout_step()
				elif now - lastidle > 10:
					lastidle = now
					self.idle_timeout_step()
				else:
					self.console_print_step()
			except:
				self.error(traceback.format_exc())	
				
			time.sleep(max(0.1, 1 - (time.time() - start)))

	def mute_timeout_step(self):
		try:
			now = time.time()
			channels = dict(self.channels)
			for chan in channels:
				channel = channels[chan]
				mutelist = dict(channel.mutelist)
				for db_id in mutelist:
					expiretime = mutelist[db_id]['expires']
					if 0 < expiretime and expiretime < now:
						del channel.mutelist[db_id]
						channel.channelMessage('<%s> has been unmuted (mute expired).' % self.protocol.clientFromID(db_id).username)
		except:
			self.error(traceback.format_exc())

	def idle_timeout_step(self):
		now = time.time()
		for client in self.clients.values():
			if not client.logged_in and client.last_login < now - 60:
				client.SendNow("SERVERMSG timed out, no login within 60 seconds!")
				client.Remove("Connection timed out, didn't login")
			elif client.lastdata < now - 60:
				client.SendNow("SERVERMSG timed out, no data or PING received for >60 seconds, closing connection")
				client.Remove("Connection timed out")

	def console_print_step(self):
		try:
			while self.console_buffer:
				line = self.console_buffer.pop(0)
				print line
				if self.log:
					self.logfile.write(line+'\n')
			
			if self.logfile:
				self.logfile.flush()
		except:
			print separator
			print traceback.format_exc()
			print separator

	def error(self, error):
		error = '%s\n%s\n%s'%(separator,error,separator)
		self.console_write(error)
		for user in dict(self.usernames):
			try:
				if self.usernames[user].debug:
					for line in error.split('\n'):
						if line:
							self.usernames[user].Send('SERVERMSG %s'%line)
			except KeyError: pass # the user was removed

	def console_write(self, lines=''):
		if type(lines) in(str, unicode):
			lines = lines.split('\n')
		elif not type(lines) in (list, tuple, set):
			try: lines = [lines.__repr__()]
			except: lines = ['Failed to print lines of type %s'%type(lines)]
		strtime = datetime.datetime.fromtimestamp(int(time.time())).isoformat() + ' '
		for line in lines:
			self.console_buffer += [ strtime + line ]

	
	def multicast(self, clients, msg, ignore=()):
		if type(ignore) in (str, unicode): ignore = [ignore]
		static = []
		for client in clients:
			if client and not client.username in ignore:
				if client.static: static.append(client)
				else: client.Send(msg)
		
		# this is so static clients don't respond before other people even receive the message
		for client in static:
			client.Send(msg)
	
	def broadcast(self, msg, chan=None, ignore=()):
		if type(ignore) in (str, unicode): ignore = [ignore]
		try:
			if chan in self.channels:
				channel = self.channels[chan]
				if len(channel.users) > 0:
					clients = [self.clientFromUsername(user) for user in list(channel.users)]
					self.multicast(clients, msg, ignore)
			else:
				clients = [self.clientFromUsername(user) for user in list(self.usernames)]
				self.multicast(clients, msg, ignore)
		except: self.error(traceback.format_exc())

	def broadcast_battle(self, msg, battle_id, ignore=[]):
		if type(ignore) in (str, unicode): ignore = [ignore]
		if battle_id in self.battles:
			battle = self.battles[battle_id]
			clients = [self.clientFromUsername(user) for user in list(battle.users)]
			self.multicast(clients, msg, ignore)

	def admin_broadcast(self, msg):
		for user in dict(self.usernames):
			client = self.usernames[user]
			if 'admin' in client.accesslevels:
				client.Send('SERVERMSG Admin broadcast: %s'%msg)

	def _rebind_slow(self):
		try:
			self.parseFiles()
		except:
			self.error(traceback.format_exc())
		
		try:
			self.dispatcher.rebind()
				
			for channel in dict(self.channels): # hack, but I guess reloading is all a hack :P
				chan = self.channels[channel].copy()
				del chan['name'] # 'cause we're passing it ourselves
				self.channels[channel] = sys.modules['protocol.Protocol'].Channel(self, channel, **chan)
			
			self.protocol = Protocol(self, None)
		except:
			self.error(traceback.format_exc())
			
		self.admin_broadcast('Done reloading.')
		self.console_write('Done reloading.')

	def reload(self):
		self.admin_broadcast('Reloading...')
		self.console_write('Reloading...')
		self.rotatelogfile()
		self.parseFiles()
		reload(sys.modules['SayHooks'])
		reload(sys.modules['protocol.AutoDict'])
		reload(sys.modules['protocol.Channel'])
		reload(sys.modules['protocol.Battle'])
		reload(sys.modules['protocol.Protocol'])
		reload(sys.modules['protocol'])
		reload(sys.modules['ChanServ'])
		reload(sys.modules['Client'])
		reload(sys.modules['SQLUsers'])
		self.SayHooks = __import__('SayHooks')
		ip2country.reloaddb()
		thread.start_new_thread(self._rebind_slow, ()) # why should reloading block the thread? :)

	def rotatelogfile(self):
		self.log = False
		try:
			if self.logfile:
				self.console_print_step() # flush logfile
				self.logfile.close()
			oldfilename = self.logfilename + ".old"
			if os.path.exists(oldfilename):
				os.remove(oldfilename)
			os.rename(self.logfilename, oldfilename)
		except OSError as e:
			print("Error rotaing logfile %s"% (e.strerror))
		except IOError as e:
			print("Error rotaing logfile %s"% (e.strerror))
		self.logfile = file(self.logfilename, 'w')
		print 'Logging enabled at: %s' % self.logfilename
		self.log = True

