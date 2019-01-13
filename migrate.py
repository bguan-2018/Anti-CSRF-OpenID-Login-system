import cgi
import json
from datetime import datetime
from google.appengine.ext import ndb
import webapp2
import logging
from user import User
from event import Event
from session import Session

class Migrate(webapp2.RequestHandler):
	def post(self):
		try:
			session = Session.get_session(self)
			if len(session) == 0 or session[0].is_expired():
				self.response.write(json.dumps(dict(redirect_url='/login', status='User not logged in.')))
				return
			current_user = User.user_exist(session[0].linked_username)
			if len(current_user) > 0:
				counter = 0
				for event in Event.query().order(-Event.date).fetch():
					new_event = Event(parent=current_user[0].key,title=event.title, content=event.content, date=event.date)  
					new_event.put()
					event.key.delete()
					counter+=1
				self.response.write(json.dumps({'status':'Successfully migrated ' + str(counter) + ' events.'}))
		except Exception as e:
			self.response.write(json.dumps({'status':'Failed to migrate records'}))
			logging.exception(e)

app = webapp2.WSGIApplication([
	('/migrate', Migrate)
], debug=True)