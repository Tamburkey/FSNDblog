from handlers import BlogHandler
from models import *
from google.appengine.ext import db


class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if self.user.key() == post.creator.key():
                self.render("deletepost.html", post=post)
            else:
                self.error(404)
                return
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        # make sure post exists
        if not post:
            self.error(404)
            return
        # make sure current user is post.creator
        if self.user.key() == post.creator.key():
            comments = db.GqlQuery("select * from Comment order by created")
            for c in comments:
                if c.comment_post_id == key:
                    c.delete()
            post.delete()
            self.redirect('/completed')
        else:
            self.redirect('/')
