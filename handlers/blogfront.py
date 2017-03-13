from models import Post
from models import Comment
from handlers import BlogHandler
from google.appengine.ext import db


class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by last_modified \
                            desc limit 10")
        comments = db.GqlQuery("select * from Comment order by created")
        self.render('front.html', posts=posts, comments=comments)
