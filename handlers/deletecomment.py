from handlers import BlogHandler
from models import *
from google.appengine.ext import db


class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        pkey = db.Key.from_path('Post', int(post_id))
        post = db.get(pkey)
        if not comment:
            self.error(404)
            return
        if self.user:
            if self.user.name == comment.creator:
                self.render('deletecomment.html', comment=comment, p=post)
            else:
                self.error(404)
                return
        else:
            self.redirect('/login')
        # make sure comment exists
        

    def post(self, post_id, comment_id):
        p_key = db.Key.from_path('Post', int(post_id))
        post = db.get(p_key)
        # make sure post exists
        if not post:
            self.error(404)
            return
        post.comment_count -= 1
        post.put()
        c_key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(c_key)
        if self.user:
            if comment:
                if self.user.name == comment.creator:
                    comment.delete()
                    self.redirect('/completed')
        else:
            self.redirect('/login')
