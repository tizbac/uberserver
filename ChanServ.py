import time

class ChanServ:
	def __init__(self, client, root):
		self.client = client
		self._root = root
		
	
	def onLogin(self):
		self.client.status = self.client._protocol._calc_status(self.client, 0)
		self.Send('JOIN main')
	
	def Handle(self, msg):
		if msg.count(' '):
			cmd, args = msg.split(' ', 1)
			if cmd == 'SAID':
				self.handleSAID(args)
			if cmd == 'SAIDPRIVATE':
				self.handleSAIDPRIVATE(args)
	
	def handleSAID(self, msg):
		chan, user, msg = msg.split(' ',2)
		self.HandleMessage(chan, user, msg)

	def handleSAIDPRIVATE(self, msg):
		user, msg = msg.split(' ', 1)
		self.HandleMessage(None, user, msg)

	def HandleMessage(self, chan, user, msg):
		if msg.startswith('!'):
			msg = msg.lstrip('!')
			if msg.lower() == 'help':
				help = self.Help(user)
				self.Send(['SAYPRIVATE %s %s'%(user, s) for s in help.split('\n')])
			else:
				args = None
				if msg.count(' ') >= 2:	# case cmd blah blah+
					splitmsg = msg.split(' ',2)
					if splitmsg[1].startswith('#'): # case cmd #chan arg+
						cmd, chan, args = splitmsg
						chan = chan.lstrip('#')
					else: # case cmd arg arg+
						cmd, args = msg.split(' ',1)
				elif msg.count(' ') == 1: # case cmd arg
					splitmsg = msg.split(' ')
					if splitmsg[1].startswith('#'): # case cmd #chan
						cmd, chan = splitmsg
						chan = chan.lstrip('#')
					else: # case cmd arg
						cmd, args = splitmsg
				else: # case cmd
					cmd = msg
				if not chan: return
				response = self.HandleCommand(chan, user, cmd, args)
				if response: self.Send('SAYPRIVATE %s %s ' % (user, response))

	def Help(self, user):
		return 'Hello, %s!\nI am an automated channel service bot,\nfor the full list of commands, see http://taspring.clan-sy.com/dl/ChanServCommands.html\nIf you want to go ahead and register a new channel, please contact one of the server moderators!' % user
	
	def HandleCommand(self, chan, user, cmd, args=None):
		print chan, user, cmd, args
		
		client = self.client._protocol.clientFromUsername(user)
		cmd = cmd.lower()
		
		if chan in self._root.channels:
			channel = self._root.channels[chan]
			access = channel.getAccess(client)
			if cmd == 'info':
				print chan, user, cmd, args
				founder = channel.owner
				if founder: founder = 'Founder is <%s>'%founder
				else: founder = 'No founder is registered'
				admins = channel.admins
				users = channel.users
				antispam = 'on' if channel.antispam.enabled else 'off'
				if not admins: mods = 'no operators are registered'
				else: mods = '%i registered operator(s) are <%s>' % (len(admins), '>, <'.join(admins))
				if len(users) == 1: users = '1 user'
				else: users = '%i users' % len(users)
				return '#%s info: Anti-spam protection is %s. %s, %s. %s currently in the channel.' % (chan, antispam, founder, mods, users)
			if cmd == 'topic':
				if access in ['mod', 'founder', 'op']:
					channel.setTopic(client, args)
					return '#%s: Topic changed' % chan
				else:
					return '#%s: You do not have permission to set the topic' % chan
			if cmd == 'unregister':
				if access in ['mod', 'founder']:
					channel.owner = ''
					channel.channelMessage('Channel has been unregistered')
					self.Send('LEAVE %s' % chan)
					return '#%s: Successfully unregistered.' % chan
				else:
					return '#%s: You must contact one of the server moderators or the owner of the channel to unregister a channel' % chan
			if cmd == 'changefounder':
				if access in ['mod', 'founder']:
					if not args: return '#%s: You must specify a new founder' % chan
					channel.changeFounder(client, self.client._protocol.clientFromUsername(args))
					channel.channelMessage('%s Founder has been changed to <%s>' % (chan, args))
					return '#%s: Successfully changed founder to <%s>' % (chan, args)
				else:
					return '#%s: You must contact one of the server moderators or the owner of the channel to change the founder' % chan
			if cmd == 'spamprotection':
				if access in ['mod', 'founder']:
					antispam = channel.antispam
					if antispam.quiet: antispam.quiet = 'on'
					else: antispam.quiet = 'off'
					status = 'on (settings: timeout:%(timeout)i, quiet:%(quiet)s, aggressiveness:%(aggressiveness)i, bonuslength:%(bonuslength)i, duration:%(duration)i)' % antispam.copy()
					if args == 'on':
						channel.antispam.enabled = True
						antispam = channel.antispam
						channel.channelMessage('%s Anti-spam protection was enabled by <%s>' % (chan, args, user))
						return '#%s: Anti-spam protection is %s' % (chan, status)
					elif args == 'off':
						channel.antispam.enabled = False
						channel.channelMessage('%s Anti-spam protection was disabled by <%s>' % (chan, args, user))
						return '#%s: Anti-spam protection is off' % chan
				if not antispam.enabled: status = 'off'
				return '#%s: Anti-spam protection is %s' % (chan, status)
			if cmd == 'spamsettings':
				if access in ['mod', 'founder']:
					antispam = channel.antispam
					if args: spaces = args.count(' ')
					else: spaces = 0
					if spaces == 4:
						timeout, quiet, aggressiveness, bonuslength, duration = args.split(' ')
						if ('%i%i%i%i' % (timeout, aggressiveness, bonuslength, duration)).isdigit() and quiet in ('on', 'off'):
							channel.antispam.update({'timeout':int(timeout), 'aggressiveness':int(aggressiveness), 'bonuslength':int(bonuslength), 'duration':int(duration), 'quiet':(quiet=='on')})
					return '#%s: Error: Invalid args for spamsettings. Valid syntax is "!spamsettings <timeout> <quiet> <agressiveness> <bonuslength> <duration>". All args but quiet are integers, which is "on" or "off".' % chan
			if cmd == 'op':
				if access in ['mod', 'founder']:
					if not args: return '#%s: You must specify a user to op' % chan
					if self.client._protocol.clientFromUsername(args) and channel.isOp(self.client._protocol.clientFromUsername(args)): return '#%s: <%s> was already an op' % (chan, args)
					channel.opUser(self.client._protocol.clientFromUsername(args))
				else:
					return '#%s: You do not have permission to op users' % chan
			if cmd == 'deop':
				if access in ['mod', 'founder']:
					if not args: return '#%s: You must specify a user to deop' % chan
					if self.client._protocol.clientFromUsername(args) and channel.isOp(args): return '#%s: <%s> was not an op' % (chan, args)
					channel.deopUser(self.client._protocol.clientFromUsername(args))
				else:
					return '#%s: You do not have permission to deop users' % chan
			if cmd == 'chanmsg':
				if access in ['mod', 'founder', 'op']:
					if not args: return '#%s: You must specify a channel message' % chan
					if self.client._protocol.clientFromUsername(args) and channel.isOp(args): args = 'issued by <%s>: %s' % (user, args)
					channel.channelMessage('%s %s' % (chan, args))
					return #return '#%s: insert chanmsg here'
				else:
					return '#%s: You do not have permission to issue a channel message' % chan
			if cmd == 'lock':
				if access in ['mod', 'founder', 'op']:
					if not args: return '#%s: You must specify a channel key to lock a channel' % chan
					channel.key = args
					self._root.broadcast('CHANNELMESSAGE %s Channel locked by <%s>' % (chan, user), chan)
					return '#%s: Locked' % chan
				else:
					return '#%s: You do not have permission to lock the channel' % chan
			if cmd == 'unlock':
				if access in ['mod', 'founder', 'op']:
					channel.key = None
					self._root.broadcast('CHANNELMESSAGE %s Channel unlocked by <%s>' % (chan, user), chan)
					return '#%s: Unlocked' % chan
				else:
					return '#%s: You do not have permission to unlock the channel' % chan
			if cmd == 'kick':
				if access in ['mod', 'founder', 'op']:
					if not args: return '#%s: You must specify a user to kick from the channel' % chan
					if args.count(' '): 
						target, reason = args.split(' ', 1)
						reason = '(reason: %s)' % reason
					else:
						target = args
						reason = ''
					if target in channel.users:
						self._root.broadcast('CHANNELMESSAGE %s <%s> kicked from the channel by <%s> %s' % (chan, target, user, reason), chan)
						channel.users.remove(target)
						self._root.broadcast('LEFT %s %s kicked from channel.'%(chan, args), chan)
					else: return '#%s: <%s> not in channel' % (chan, target)
					return '#%s: <%s> kicked' % (chan, target)
				else:
					return '#%s: You do not have permission to kick users from the channel' % chan
			if cmd == 'mute':
				if access in ['mod', 'founder', 'op']:
					if not args: return '#%s: You must specify a user to mute' % chan
					else:
						if args.count(' '): target, duration = args.split(' ', 1)
						else:
							target = args
							duration = -1
					try:
						duration = float(duration)*60
						if duration < 1:
							timeleft = -1
						else:
							timeleft = time.time() + duration
					except ValueError:
						return '#%s:  Duration must be an integer!' % chan
					channel.muteUser(client, self.client._protocol.clientFromUsername(target), duration)
				else:
					return '#%s: You do not have permission to mute users' % chan
			if cmd == 'unmute':
				if access in ['mod', 'founder', 'op']:
					if not args: return '#%s: You must specify a user to unmute' % chan
					channel.unmuteUser(client, self.client._protocol.clientFromUsername(args))
				else:
					return '#%s: You do not have permission to unmute users' % chan
			if cmd == 'mutelist':
				if len(channel.mutelist):
					mutelist = dict(channel.mutelist)
					muted = '#%s: Mute list (%i entries):  '%(chan, len(mutelist))
					for user in mutelist:
						timeleft = mutelist[user]
						if timeleft < 0:
							timeleft = 'indefinite'
						else:
							timeleft = timeleft-time.time()
						muted += '%s, %s seconds remaining; '%(user, timeleft)
					return muted
				else:
					return '#%s: Mute list is empty!' % chan
		if client.isMod():
			if cmd == 'register':
				print 'register', args
				if not args: args = user
				self.Send('JOIN %s' % chan)
				channel = self._root.channels[chan]
				channel.setFounder(client, self.client._protocol.clientFromUsername(args))
				channel.channelMessage('#%s Channel has been registered to <%s>' % (chan, args))
				return '#%s: Successfully registered to <%s>' % (chan, args.split(' ',1)[0])
		elif not chan in self._root.channels:
				return '#%s: You must contact one of the server moderators or the owner of the channel to register a channel' % chan
		else:
			return '#%s is not registered.' % chan
		return ''
	
	def Send(self, msg):
		if type(msg) == list or type(msg) == tuple:
			for s in msg:
				self.client._protocol._handle( self.client, s )
		elif type(msg) == str:
			if '\n' in msg:
				for s in msg.split('\n'):
					self.client._protocol._handle( self.client, s )
			else:
				self.client._protocol._handle( self.client, msg )

class Client:
	'this object is chanserv implemented through the standard client interface'

	def __init__(self, root, address, session_id, country_code):
		'initial setup for the connected client'
		
		self.static = True # can't be removed... don't want to anyway :)
		self._protocol = False
		self.removing = False
		self.msg_id = ''
		self.sendingmessage = ''
		self._root = root
		self.ip_address = address[0]
		self.local_ip = address[0]
		self.logged_in = True
		self.port = address[1]
		self.conn = False
		self.country_code = country_code
		self.session_id = session_id
		self.status = '12'
		self.access = 'admin'
		self.accesslevels = ['admin', 'mod', 'user', 'everyone']
		self.channels = []
		self.username = ''
		self.password = ''
		self.hostport = 8542
		self.blind_channels = []
		self.debug = False
		
		self._root.console_write( 'ChanServ connected from %s, session ID %s.' % (self.ip_address, session_id) )
		
		self.ingame_time = 0
		self.bot = 1
		self.username = 'ChanServ'
		self.password = 'ChanServ'
		self.cpu = '9001'
		self.local_ip = None
		self.hook = ''
		self.went_ingame = 0
		self.local_ip = self.ip_address
		self.lobby_id = 'ChanServ'
		self._root.usernames[self.username] = self
		self._root.console_write('Successfully logged in static user <%s> on session %s.'%(self.username, self.session_id))
		
		now = time.time()
		self.last_login = now
		self.register_date = now
		self.lastdata = now
		
		self.users = [] # session_id
		self.userqueue = {} # [session_id] = [{'type': ['message', 'remove'], 'data':['CLIENTSTATUS', '']}, etc]
		self.battles = {} # [battle_id] = [user1, user2, user3, etc]
		self.battlequeue = {} # [battle_id] = [{'type': ['message', 'remove'], 'data':['CLIENTBATTLESTATUS', '']}, etc]
		
	def Bind(self, handler=None, protocol=None):
		if handler:
			self.handler = handler
		self.ChanServ = ChanServ(self, self._root)
		if protocol and not self._protocol:
			self._protocol = protocol
			self.ChanServ.onLogin()
		else:
			self._protocol = protocol

	def Handle(self, data):
		pass

	def Remove(self):
		pass

	def Send(self, msg):
		self.SendNow(msg)

	def SendNow(self, msg):
		if not msg: return
		self.ChanServ.Handle(msg)

	def FlushBuffer(self):
		pass

	# Queuing
	
	def AddUser(self, user):
		if type(user) == str:
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users: return
		self.users.append(session_id)
		self._protocol.client_AddUser(self, user)
		if session_id in self.userqueue:
			while self.userqueue[session_id]:
				item = self.userqueue[session_id].pop(0)
				if item['type'] == 'remove':
					del self.userqueue[session_id]
					break
				elif item['type'] == 'message':
					self.Send(item['data'])
	
	def RemoveUser(self, user):
		if type(user) == str:
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users:
			self.users.remove(session_id)
			if session_id in self.userqueue:
				del self.userqueue[session_id]
			self._protocol.client_RemoveUser(self, user)
		else:
			self.userqueue[session_id] = [{'type':'remove'}]
	
	def SendUser(self, user, data):
		if type(user) == str:
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users:
			self.Send(data)
		else:
			if not session_id in self.userqueue:
				self.userqueue[session_id] = []
			self.userqueue[session_id].append({'type':'message', 'data':data})
	
	
	def AddBattle(self, battle):
		battle_id = battle.id
		if battle_id in self.battles: return
		self.battles[battle_id] = []
		self._protocol.client_AddBattle(self, battle)
		if battle_id in self.battlequeue:
			while self.battlequeue[battle_id]:
				item = self.battlequeue[battle_id].pop(0)
				if item['type'] == 'remove':
					del self.battlequeue[battle_id]
					break
				elif item['type'] == 'message':
					self.Send(item['data'])
	
	def RemoveBattle(self, battle):
		battle_id = battle.id
		if battle_id in self.battles:
			del self.battles[battle_id]
			if battle_id in self.battlequeue:
				del self.battlequeue[battle_id]
			self._protocol.client_RemoveBattle(self, battle)
		else:
			self.battlequeue[battle_id] = [{'type':'remove'}]
	
	def SendBattle(self, battle, data):
		battle_id = battle.id
		if battle_id in self.battles:
			self.Send(data)
		else:
			if not battle_id in self.battlequeue:
				self.battlequeue[battle_id] = []
			self.battlequeue[battle_id].append({'type':'message', 'data':data})