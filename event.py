from google.appengine.ext import ndb

class Event(ndb.Model):
	date = ndb.DateTimeProperty(auto_now_add=True)
	title = ndb.StringProperty()
	content = ndb.StringProperty()

	#query_all takes the event table itself and orders all by the event date in descending order 
	@classmethod
	def query_all(cls, user_key):
		return cls.query(ancestor=user_key).order(-cls.date)