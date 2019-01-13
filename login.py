import os
import cgi
import json
import uuid
from datetime import datetime
from datetime import timedelta
from google.appengine.ext import ndb
from google.appengine.api import urlfetch
import webapp2
import jinja2
import logging
import urllib
import base64
from user import User, LoginType
from event import Event
from session import Session
from secret import Secret


JINJA_ENVIRONMENT = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)), extensions=['jinja2.ext.autoescape'], autoescape=True)
API_ACCESS_TOKEN_URL = 'https://www.googleapis.com/oauth2/v4/token'
CLIENT_ID = '1043585523036-fsgfu529umcipanl06ilokpi4egrqolv.apps.googleusercontent.com'

class Login(webapp2.RequestHandler):
	def get(self):
		try:
			csrf_token = str(uuid.uuid4())
			nonce = str(uuid.uuid4())
			template_values = {
				'client_id': CLIENT_ID,
				'state': csrf_token,
				'nonce': nonce,
				'redirect_uri': self.request.host_url + '/oidcauth'
			}
			domain = '' if 'localhost' in self.request.host else self.request.host
			self.response.set_cookie('csrf_token', csrf_token, max_age=3600, path='/', domain=domain)
			self.response.set_cookie('nonce', nonce, max_age=3600, path='/', domain=domain)		
			template = JINJA_ENVIRONMENT.get_template('login.html')
			self.response.write(template.render(template_values))
		except Exception as e:
			logging.exception(e)
	def post(self):
		try:
			json_user = json.loads(self.request.body)
			username = json_user.get('username').encode("utf-8")
			password = json_user.get('password').encode("utf-8")
			json_response = User.create_user(self, username, password, LoginType.LOGIN)
			self.response.write(json_response)
		except Exception as e: 
			self.response.write(json.dumps({'status':'Failed to login.'}))
			logging.exception(e)

class Oidcauth(webapp2.RequestHandler):
	def get(self):
		state = self.request.params['state']
		if state == self.request.cookies.get('csrf_token'):
			domain = '' if 'localhost' in self.request.host else self.request.host
			self.response.set_cookie('csrf_token', '', max_age=0, path='/', domain=domain)	
			headers = {'Content-Type': 'application/x-www-form-urlencoded'}
			payload = {
					   "grant_type": "authorization_code",
					   "code": self.request.params["code"],
					   "client_id": CLIENT_ID,
					   "client_secret": ndb.Key(Secret, "oidc_client").get().value,
					   "redirect_uri": self.request.host_url + "/oidcauth"
			}
			result = urlfetch.fetch(url=API_ACCESS_TOKEN_URL, 
									payload=urllib.urlencode(payload), 
									method=urlfetch.POST, 
									headers=headers)
			_, body, _ = json.loads(result.content)['id_token'].split('.')
			body += '=' * (-len(body) % 4)
			claims = json.loads(base64.b64decode(body))
			nonce = claims['nonce']
			if nonce == self.request.cookies.get('nonce'):
				User.create_user(self, claims['email'], claims['sub'], LoginType.GOOGLE_LOGIN)
				self.redirect('/index.html')
			else:
				self.redirect('/login')

class Register(webapp2.RequestHandler):
	def get(self):
		template = JINJA_ENVIRONMENT.get_template('register.html')
		self.response.write(template.render())
	def post(self):
		try:
			json_user = json.loads(self.request.body)
			username = json_user.get('username').encode("utf-8")
			password = json_user.get('password').encode("utf-8")
			json_response = User.create_user(self, username, password, LoginType.REGISTER)
			self.response.write(json_response)
		except Exception as e: 
			self.response.write(json.dumps({'status':'Failed to register.'}))
			logging.exception(e)

class Logout(webapp2.RequestHandler):
	def post(self):
		try:
			domain = '' if 'localhost' in self.request.host else self.request.host
			session = Session.get_session(self)
			if len(session) > 0:
				session[0].key.delete()
			self.response.set_cookie('token', '', max_age=0, path='/', domain=domain)	
			self.response.write(json.dumps(dict(redirect_url='/login', status='success')))
		except Exception as e: 
			self.response.write(json.dumps({'status':'Failed to logout the user.'}))
			logging.exception(e)

class UserInfo(webapp2.RequestHandler):
	def post(self):
		try:
			session_info = json.loads(self.request.body)
			session_token = session_info.get('token')
			session = Session.query(Session.session_token==session_token).fetch()
			if len(session) > 0:
				self.response.write(json.dumps(dict(username=session[0].linked_username, status='success')))
			else: 
				self.response.write(json.dumps(dict(status='Failed to retreive user information.')))
		except Exception as e: 
			self.response.write(json.dumps({'status':'Failed to retreive user information.'}))
			logging.exception(e)

app = webapp2.WSGIApplication([
	('/login', Login),
	('/register', Register),
	('/logout', Logout),
	('/getuser', UserInfo),
	('/oidcauth', Oidcauth)
], debug=True)