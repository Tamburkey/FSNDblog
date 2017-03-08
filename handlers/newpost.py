from models import User
from models import Post
from handlers import BlogHandler

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        creator = self.user.key()
        likes = 0

        # make sure all required post properties exist
        if subject and content and creator:
            # create post
            p = Post(subject=subject, content=content,
                        creator=creator, likes=likes)
            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)
