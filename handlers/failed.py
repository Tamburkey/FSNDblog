from handlers import BlogHandler


class Failed(BlogHandler):
    def get(self):
        self.render('failed.html')
