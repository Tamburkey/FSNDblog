from handlers import BlogHandler
from models import *
from google.appengine.ext import db

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        # make sure comment exists
        if not comment:
            self.error(404)
            return
        self.render('deletecomment.html', comment=comment)

    def post(self, post_id, comment_id):
        p_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(p_key)
        # make sure post exists
        if not post:
            self.error(404)
            return
        post.comment_count -= 1
        post.put()
        c_key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(c_key)
        comment.delete()
        self.redirect('/completed')
