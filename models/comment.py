from google.appengine.ext import db


class Comment(db.Model):
    comment = db.StringProperty()
    comment_post_id = db.StringProperty()
    creator = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
