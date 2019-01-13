import json
import bcrypt
import logging
import webapp2
from datetime import datetime
from datetime import timedelta
from google.appengine.ext import ndb
from session import Session

class LoginType():
	LOGIN = 1
	GOOGLE_LOGIN = 2
	REGISTER = 3

class User(ndb.Model):

	username = ndb.StringProperty()
	password = ndb.StringProperty()
	@classmethod
	def verify_password(self, plain_pwd, hashed_pwd):
		if bcrypt.hashpw(plain_pwd, hashed_pwd) == hashed_pwd:
			return True
		else:
			return False
	@classmethod
	def hash_password(self, plain_pwd):
		salt = bcrypt.gensalt()
		hashed_pwd = bcrypt.hashpw(plain_pwd, salt)
		return hashed_pwd

	@classmethod
	def user_exist(cls, username):
		return cls.query(User.username==username).fetch()

	@classmethod
	def create_user(self, request_handler, username, password, login_type):
		try:
			current_user = User.user_exist(username)
			if login_type == LoginType.LOGIN:
				if len(current_user) <= 0: 
					return json.dumps({'status':'User doesn\'t exist.'})
				elif not User.verify_password(password, current_user[0].password):
					return json.dumps({'status':'Wrong user password, please try again.'})
				session = Session(session_token=Session.generate_session_token(), linked_username=username, expiration_date=datetime.now()+timedelta(seconds=3600))
			elif login_type == LoginType.GOOGLE_LOGIN:
				if len(current_user) <= 0: 
					sub = password
					current_user = User(username=username)
					current_user.key = ndb.Key(User, sub)
					current_user.put()
				session = Session(session_token=Session.generate_session_token(), linked_username=username, expiration_date=datetime.now()+timedelta(seconds=3600))
			elif login_type == LoginType.REGISTER:
				if len(current_user) > 0:
					return json.dumps({'status':'User already exists!'})
				else:
					current_user = User(username=username, password=User.hash_password(password))
					current_user.put()
				session = Session(session_token=Session.generate_session_token(), linked_username=username, expiration_date=datetime.now()+timedelta(seconds=3600))
			session.put()
			domain = '' if 'localhost' in request_handler.request.host else request_handler.request.host
			request_handler.response.set_cookie('token', session.session_token, max_age=3600, path='/', domain=domain)		
			if login_type in (LoginType.LOGIN, LoginType.REGISTER):
				return json.dumps(dict(redirect_url='/index.html', status='success'))
			elif login_type == LoginType.GOOGLE_LOGIN:
				return '/index.html'
		except Exception as e: 
			logging.exception(e)
			return json.dumps({'status':'Failed to login.'})
			 