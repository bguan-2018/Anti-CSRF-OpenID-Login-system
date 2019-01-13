from google.appengine.ext import ndb
import webapp2

class Secret(ndb.Model):
	name = ndb.StringProperty() 
	value = ndb.StringProperty()

class Init(webapp2.RequestHandler): 
	@ndb.transactional
 	def get(self):
		key = ndb.Key(Secret, "oidc_client")
		if key.get():
 			return self.response.write("Already exists") 
 		Secret(key=key, name=key.id(), value="").put() 
 		self.response.write("Success")

app = webapp2.WSGIApplication([
	('/init', Init)
], debug=True)