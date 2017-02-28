import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

file = open('secret.txt', 'r')
secret = file.read()

# functions for validating user sign-up input
def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)


# template rendering
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# create a secure value for cookies
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


# validation of secure val
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)

# User entity in google data store
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    liked = db.StringProperty(default='')

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u


    # hash password before storing
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# Post entity in google data store
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    # TODO get ReferenceProperty type to function for creator
    creator = db.StringProperty(required=True)
    likes = db.IntegerProperty()
    comment_count = db.IntegerProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

# Comment entity in google data store
class Comment(db.Model):
    comment = db.StringProperty()
    comment_post_id = db.StringProperty()
    creator = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

# query google data store for posts and comments and render front-page
class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by last_modified \
                            desc limit 10")
        comments = db.GqlQuery("select * from Comment order by created")
        self.render('front.html', posts=posts, comments=comments)

# create specific post page w/ comments for each post in the database
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
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
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
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
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            self.redirect('/%s' % str(post.key().id()))


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')
        creator = self.user.name
        likes = 0

        # make sure all required post properties exist
        if subject and content and creator:
            # create post
            p = Post(parent=blog_key(), subject=subject,
                     content=content, creator=creator, likes=likes)
            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        # error handling for invalid input
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


class BlogWelcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            self.render("editpost.html", p=post)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        # make sure subject and content are not blank
        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            # make sure post exists
            if not post:
                self.error(404)
                return
            # make sure current user is post.creator
            if self.user.name == post.creator:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/%s' % str(post.key().id()))
            else:
                self.error(404)
                return

        else:
            error = "subject and content, please!"
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            self.render("editpost.html", p=post, subject=subject,
                        content=content, error=error)


class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            self.render("deletepost.html", post=post)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        # make sure post exists
        if not post:
            self.error(404)
            return
        # make sure current user is post.creator
        if self.user.name == post.creator:
            comments = db.GqlQuery("select * from Comment order by created")
            for c in comments:
                if c.comment_post_id == key:
                    c.delete()
            post.delete()
            self.redirect('/completed')

# page for completed action so that front page refreshes properly
class Completed(BlogHandler):
    def get(self):
        self.render('completed.html')

# page for failed action so that front page refreshes properly
class Failed(BlogHandler):
    def get(self):
        self.render('failed.html')


class Like(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            # make sure post exists
            if not post:
                self.error(404)
                return
            # make sure post.likes is not None
            if not post.likes:
                post.likes = 0
            # make sure user is not liking own post  
            # and hasn't already liked the post
            if self.user.name != post.creator and \
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


class DeleteComment(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        # make sure comment exists
        if not comment:
            self.error(404)
            return
        self.render('deletecomment.html', comment=comment)

    def post(self, post_id, comment_id):
        p_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(p_key)
        # make sure post exists
        if not post:
            self.error(404)
            return
        post.comment_count -= 1
        post.put()
        c_key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(c_key)
        comment.delete()
        self.redirect('/completed')


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
