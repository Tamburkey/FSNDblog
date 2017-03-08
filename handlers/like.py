from models import User
from models import Post
from handlers import BlogHandler
from google.appengine.ext import db

class Like(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            # make sure post exists
            if not post:
                self.error(404)
                return
            # make sure post.likes is not None
            if not post.likes:
                post.likes = 0
            # make sure user is not liking own post  
            # and hasn't already liked this post
            if self.user.key() != post.creator.key() and \
                    str(post.key().id()) not in self.user.liked:
                post.likes += 1
                self.user.liked += str(post.key().id()) + ','
                self.user.put()
                post.put()
                self.redirect('/completed')
            if str(post.key().id()) in self.user.liked:
                error = "Cannot like a post more than once"
                self.render('failed.html', error=error)
            else:
                error = "Cannot like your own posts"
                self.render('failed.html', error=error)

        else:
            self.redirect("/login")
