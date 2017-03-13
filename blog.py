import webapp2
from models import *
from handlers import *


app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', BlogWelcome),
                               ('/edit/([0-9]+)', EditPost),
                               ('/delete/([0-9]+)', DeletePost),
                               ('/completed', Completed),
                               ('/like/([0-9]+)', Like),
                               ('/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/editcomment/([0-9]+)/([0-9]+)', EditComment),
                               ('/failed', Failed)
                               ],
                              debug=True)
