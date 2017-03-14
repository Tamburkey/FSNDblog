from handlers import BlogHandler
from models import User
from models import Post
from google.appengine.ext import db


class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if self.user:
            if self.user.key() == post.creator.key():
                self.render("editpost.html", p=post)
            else:
                self.redirect("/failed")
        else:
            self.redirect('/login')

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')

        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        # make sure post exists
        if not post_exists(self, post):
            self.error(404)
            return
        # make sure current user is post.creator
        if self.user.key() == post.creator.key():
            subject = self.request.get('subject')
            content = self.request.get('content')
        # make sure subject and content are not blank
            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/%s' % str(post.key().id()))
            else:
                error = "subject and content, please!"
                key = db.Key.from_path('Post', int(post_id))
                post = db.get(key)
                self.render("editpost.html", p=post, subject=subject,
                            content=content, error=error)

        else:
            self.error(404)
            return
