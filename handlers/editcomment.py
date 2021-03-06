from handlers import BlogHandler
from models import *
from google.appengine.ext import db


class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        pkey = db.Key.from_path('Post', int(post_id))
        post = db.get(pkey)
        # make sure comment exists
        if not comment:
            self.error(404)
            return
        if self.user:
            if self.user.name == comment.creator:
                self.render('editcomment.html', comment=comment, p=post)
            else:
                self.error(404)
                return
        else:
            self.redirect('/login') 

    def post(self, post_id, comment_id):
        comment_content = self.request.get('comment-content')
        if self.user:
            if comment_content:
                key = db.Key.from_path('Comment', int(comment_id))
                comment = db.get(key)
                if not comment:
                    self.error(404)
                    return
                # make sure current user is comment.creator
                if self.user.name == comment.creator:
                    comment_content = self.request.get('comment-content')
                    comment.comment = comment_content
                    comment.put()
                    self.redirect('/completed')
                else:
                    self.error(404)
                    return
            else:
                error = "Cannot leave blank comments!"
                key = db.Key.from_path('Comment', int(comment_id))
                comment = db.get(key)
                self.render("editcomment.html", comment=comment, error=error)
