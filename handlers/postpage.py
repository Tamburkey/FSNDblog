from models import *
from handlers import BlogHandler
from google.appengine.ext import db


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        # iterate over comments in permalink.html to generate post comments
        comments = db.GqlQuery("select * from Comment order by created")
        # make sure post exists
        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, comments=comments,
                    post_id=str(post.key().id()))

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')

        # comment creation
        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            # make sure post.comment_count is not None
            if not post.comment_count:
                post.comment_count = 0
            post.comment_count += 1
            post.put()
            comment_post_id = str(post.key().id())
            creator = self.user.name
            c = Comment(comment=comment, comment_post_id=comment_post_id,
                        creator=creator)
            c.put()
            self.redirect('/completed')
        else:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            self.redirect('/%s' % str(post.key().id()))
