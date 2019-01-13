import random
import datetime
import logging
from google.appengine.ext import ndb


class Session(ndb.Model):

	session_token = ndb.StringProperty()
	linked_username = ndb.StringProperty()
	expiration_date = ndb.DateTimeProperty()

	@classmethod
	def generate_session_token(cls):
		return repr(random.getrandbits(128))

	@classmethod
	def get_session(cls, request_handler):
		token = request_handler.request.cookies.get('token')			
		if token:
			return cls.query(Session.session_token==token).fetch()
		else:
			return False	
	
	def is_expired(self):
		return self.expiration_date < datetime.datetime.now()

