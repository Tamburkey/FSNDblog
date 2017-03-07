from handlers import BlogHandler

class Completed(BlogHandler):
    def get(self):
        self.render('completed.html')
