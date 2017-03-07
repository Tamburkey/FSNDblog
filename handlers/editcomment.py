from handlers import BlogHandler
from models import *
from google.appengine.ext import db


class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        # make sure comment exists
        if not comment:
            self.error(404)
            return
        self.render('editcomment.html', comment=comment)

    def post(self, post_id, comment_id):
        comment_content = self.request.get('comment-content')
        if comment_content:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
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
