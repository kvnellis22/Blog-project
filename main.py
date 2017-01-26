#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import random
import hashlib
import hmac
from string import letters

import jinja2
import webapp2

from google.appengine.ext import db

from user import User
from post import Post
from comment import Comment

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = "mysecret"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val) #short way to write an if statement

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class BlogFront(Handler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = db.GqlQuery("select * from Comment where post_id = " +
            post_id + " order by created desc")


        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post, comments = comments)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        com = ""
        if self.user:
            if self.request.get('comment'):
                com = Comment(parent =blog_key(), user_id= self.user.key().id(),
                post_id = int(post_id), comment = self.request.get('comment'))
                com.put()
        else:
            self.redirect("/login")
            return

        comments = db.GqlQuery("select * from Comment where post_id = " + post_id + "order by created desc")

        self.render("permalink.html", post = post, comments = comments, new = com)

class NewPost(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')
            return

        subject = self.request.get('subject')
        content = self.request.get('content')


        if subject and content:
            p = Post(parent = blog_key(), user_id=self.user.key().id(), subject = subject, content = content)
            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "Add content and subject"
            self.render("newpost.html", subject=subject, content=content, error=error)

class Postdelete(Handler):
    def get(self, post_id,):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post: # checks to see if post exist
            if self.user:
                if post.user_id == self.user.key().id():
                    post.delete()
                    self.render("user_success.html") # change to a template that says successful deletion
                else:
                    self.render("user_error.html")# change to a template no access to delete
            else:
                self.redirect("/login")# change to a template not logged in | login
        else:
            self.render("post_error.html")

class Postedit(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post: # checks to see if post exist
            if self.user:
                if post.user_id == self.user.key().id():
                    self.render("editpost.html", subject = post.subject, content = post.content)
                else:
                    self.render("edit_error.html")# change to a template no access to edit
            else:
                self.redirect("/login")# change to a template not logged in | login
        else:
            self.render("post_error.html")


    def post(self, post_id):
        if not self.user:
            self.render("edit_error.html")
            return

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/%s' % post_id)

        else:
            error = "Add content and subject"
            self.render("editpost.html", subject=subject, content=content, error=error)


class Commentdelete(Handler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        com = db.get(key)
        if com:
            if self.user:
                if com.user_id == self.user.key().id():
                    com.delete()
                    self.redirect("/"+ post_id + "?comment_deleted=" + comment_id)
                else:
                    self.render("comment_error.html")
            else:
                self.redirect("/login")
        else:
            self.render("post_error.html")


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

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
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password) # this login function is for the user object
        if u:
            self.login(u)# login function is connected to handler
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')

class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([
    ('/', BlogFront), ('/([0-9]+)', PostPage), ('/newpost', NewPost), ('/delete/([0-9]+)', Postdelete),
    ('/deletecomment/([0-9]+/([0-9]+)', Commentdelete), ('/edit/([0-9]+)', Postedit), ('/signup', Register),
    ('/welcome', Welcome), ('/login', Login), ('/logout', Logout)], debug=True)
