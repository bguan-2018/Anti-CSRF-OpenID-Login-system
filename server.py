import cgi
import json
from datetime import datetime
from google.appengine.ext import ndb
import webapp2
import logging
from session import Session
from user import User 
from event import Event



class Encoder(json.JSONEncoder):
	#helper method taking an object to encode datetime into json string
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)


class Remove(webapp2.RequestHandler): 
	#takes an event key id and deletes from the event table
	def delete(self, id):
		session = Session.get_session(self)
		if not session or len(session) == 0 or session[0].is_expired():
			self.response.write(json.dumps(dict(redirect_url='/login', status='user not logged in')))
			return
		event_id = 'Does not exist'
		try:
			path_array = self.request.path.split('/')
			logging.info('path array: ' + repr(path_array))
			if len(path_array) > 1:
				event_id = path_array[len(path_array)-1]
				ndb.Key(urlsafe=event_id).delete()
				self.response.write(json.dumps(dict(id=repr(event_id), status='success')))
		except Exception as e:
			self.response.write(json.dumps(dict(id=repr(event_id), status='failed to delete event')))
			logging.exception(e)

class SubmitForm(webapp2.RequestHandler):
	#saves a new event by taking the title, content and date from the request.
	def post(self):
		session = Session.get_session(self)
		if not session or len(session) == 0 or session[0].is_expired():
			self.response.write(json.dumps(dict(redirect_url='/login', status='User not logged in.')))
			return
		current_user = User.user_exist(session[0].linked_username)
		if len(current_user) > 0:
			try:
				json_event = json.loads(self.request.body)
				event_title = json_event.get('title')
				event_content = json_event.get('content')  
				event_date = datetime.strptime(json_event.get('date'), '%Y-%m-%d')
				event = Event(parent=current_user[0].key,title=event_title, content=event_content, date=event_date)
				event.put()
				self.response.write(json.dumps(dict(id=repr(event.key.urlsafe()), status='success')))
			except Exception as e: 
				self.response.write(json.dumps({'status':'failed to save event'}))
				logging.exception(e)
		else:
			self.response.write(json.dumps(dict(redirect_url='/login', status='User doesn\'t exist.')))

class AllEvents(webapp2.RequestHandler):
	def date_handler(obj):
	    if hasattr(obj, 'isoformat'):
	        return obj.isoformat()
	#get all the events and return them in a json string format back to the client
	def get(self):
		try:
			session = Session.get_session(self)
			if not session or len(session) == 0 or session[0].is_expired():
				self.response.write(json.dumps(dict(redirect_url='/login', status='User is not logged in.')))
				return
			current_user = User.user_exist(session[0].linked_username)
			if len(current_user) > 0:
				all_events = [dict(e.to_dict(), **dict(id=repr(e.key.urlsafe()))) for e in Event.query_all(current_user[0].key).fetch()]
				all_events_json = json.dumps(all_events, cls=Encoder, indent=4)
				self.response.headers['Content-Type'] = 'application/json'
				self.response.out.write(all_events_json)
			else:
				self.response.write(json.dumps(dict(redirect_url='/login', status='User doesn\'t exist!')))
		except Exception as e:
			self.response.write(json.dumps(dict(status='Unable to retrieve events.')))
			logging.exception(e)

		
app = webapp2.WSGIApplication([
	('/events', AllEvents),
	('/event', SubmitForm),
	('/event/(.*)', Remove)
], debug=True)


