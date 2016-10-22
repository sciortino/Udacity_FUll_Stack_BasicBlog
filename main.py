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
import webapp2
import jinja2
import os
import re

import random
import string
import hashlib

from google.appengine.ext import ndb

template_dir = os.path.dirname(__file__) + "/templates"
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape = True)

#Security Functions
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(str(name) + str(pw) + str(salt)).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    split_str = h.split(",")[1]
    if h == make_pw_hash_withpinch(name, pw, split_str):
        return True
    else:
        return False

#Database Operations
def get_User_id(self):
    cookie = self.request.cookies.get('user_id')
    if cookie:
        return int(cookie.split('|')[0])
    else:
        return None

def get_User_obj(self):
    user_id = get_User_id(self)
    return User_class.get_by_id(int(user_id))

def check_if_logged_in(self):
    user_id = get_User_id(self)
    if user_id:
        return True
    else:
        return False

#Database Classes
class Post_class(ndb.Model):
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required = True)
    author = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add = True)

class User_class(ndb.Model):
    username_obj = ndb.StringProperty(required=True)
    password_obj = ndb.StringProperty(required = True)
    email_obj = ndb.StringProperty(required = False)
    created_obj = ndb.DateTimeProperty(auto_now_add = True)

class Likes_class(ndb.Model):
    post_id = ndb.StringProperty(required=True)
    username = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add = True)

class Comment_class(ndb.Model):
    post_id = ndb.StringProperty(required=True)
    comment = ndb.TextProperty(required=True)
    author = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add = True)

#Handler Classes
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#Blog Post Functions
def error_msg(errorCode):
    if errorCode == "editdelete":
        return "You cannot edit or delete posts that you didn't write!"
    elif errorCode == "editdelete_cmt":
        return "You cannot edit or delete comments that you didn't write!"
    elif errorCode == "like":
        return "You cannot like your own posts!"

#Display Top 10 Blog Posts
#Path: '/'
class MainHandler(Handler):
    def render_front(self):
        logged_in = check_if_logged_in(self)
        posts = ndb.gql("SELECT * FROM Post_class ORDER BY created DESC LIMIT 10 ")
        self.render("homepage.html", posts=posts, logged_in=logged_in)

    def get(self):
        self.render_front()

#Write new post
#Path: '/blog/newpost'
class PostHandler(Handler):
    def get(self):
        logged_in = check_if_logged_in(self)

        if logged_in == True:
            self.render("post.html", edit_type="New Post", logged_in = True)
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get("subject")
        blog = self.request.get("content")
        author = str(get_User_obj(self).username_obj)

        if subject and blog:
            p = Post_class(subject=subject, content=blog, author=author)
            p.put()
            self.redirect('/blog/%s' % int(p.key.id()))

        else:
            blog_err = "subject and content please!"
            self.render("post.html", edit_type="New Post", subject=subject, blog=blog, blog_err=blog_err)

#Display post
#Path: '/blog/post#'
class PostRender(Handler):
    def get(self, blog_id):
        key = ndb.Key('Post_class', int(blog_id))
        post = key.get()
        show_like = True

        error_message = ""
        errorCode = self.request.get('err')
        if errorCode:
            error_message = error_msg(errorCode)

        logged_in = check_if_logged_in(self)
        if logged_in:
            loggedin_user = str(get_User_obj(self).username_obj)
            #Check if the user has already liked this post
            q = Likes_class.query()
            q_user = q.filter(Likes_class.post_id == str(int(blog_id)))
            q_user = q_user.filter(Likes_class.username == loggedin_user)
            q_user = q_user.get()
            if q_user:
                show_like = False
        else:
             loggedin_user = ""

        #Count how many times this post has been liked
        q = Likes_class.query()
        q_post = q.filter(Likes_class.post_id == str(int(blog_id)))

        #Gather comments
        cmt = Comment_class.query()
        cmt = cmt.filter(Comment_class.post_id == str(int(blog_id)))

        self.render("blogEntry.html",
            post=post,
            logged_in=logged_in,
            edit_href='/blog/edit/%s' % int(post.key.id()),
            delete_href='/blog/delete/%s' % int(post.key.id()),
            like_href='/blog/%s/like' % int(post.key.id()),
            unlike_href='/blog/%s/unlike' % int(post.key.id()),
            error_msg=error_message,
            show_like=show_like,
            like_count=q_post.count(),
            comments=cmt,
            comment_href='/blog/%s/newcomment' % int(post.key.id()),
            blog_id=str(int(blog_id)))

#Edit existing post
#Path: '/blog/edit/post#'
class EditPost(Handler):
    def get(self, blog_id):
        logged_in = check_if_logged_in(self)
        key = ndb.Key('Post_class', int(blog_id))
        post = key.get()
        subject = post.subject
        blog = post.content

        #Test if logged-in user is the article author
        loggedin_user = str(get_User_obj(self).username_obj)
        if loggedin_user == post.author:
            self.render("post.html", edit_type="Edit Post", subject=subject, blog=blog,
                redirect_url='/blog/%s' % int(post.key.id()))
        else:
            self.redirect('/blog/%s?err=%s' % (int(post.key.id()),"editdelete"))

    def post(self, blog_id):
        key = ndb.Key('Post_class', int(blog_id))
        post = key.get()
        post.subject = self.request.get("subject")
        post.content = self.request.get("content")
        post.put()
        self.redirect('/blog/%s' % int(post.key.id()))

#"Like" Post
#Path: 'blog/post#/like'
class LikePost(Handler):
    def get(self, blog_id):
        #Check if the user is logged in
        logged_in = check_if_logged_in(self)
        if logged_in == False:
            self.redirect('/login')
        else:
            #Check if the logged in user is the author of the post
            post_id = str(int(blog_id))
            username = str(get_User_obj(self).username_obj)

            key = ndb.Key('Post_class', int(blog_id))
            post = key.get()
            if post.author == username:
                self.redirect('/blog/%s?err=%s' % (int(post.key.id()),"like"))
            else:
                #Check if the user has already liked this post
                q = Likes_class.query()
                q = q.filter(Likes_class.username == username, Likes_class.post_id == post_id)
                q = q.get()

                if q:
                    self.redirect('/blog/%s' % int(blog_id))
                else:
                    L = Likes_class(post_id = str(post_id), username = username)
                    L.put()
                    self.redirect('/blog/%s' % int(blog_id))

#Unlike Post:
#Path: '/blog/post#/unlike'
class UnlikePost(Handler):
    def get(self, blog_id):
        #Check if user is logged in
        logged_in = check_if_logged_in(self)

        if logged_in == True:
            #Check if logged-in user is author of the post
            key = ndb.Key('Post_class', int(blog_id))
            post = key.get()
            loggedin_user = str(get_User_obj(self).username_obj)

            if loggedin_user == post.author:
                #Re-render post with error
                self.redirect('/blog/%s?err=%s' % (str(int(blog_id)),"like"))
            else:
                #Delete 'Like'
                q = Likes_class.query(Likes_class.username == loggedin_user,
                    Likes_class.post_id == str(int(blog_id)))
                for row in q:
                    row.key.delete()
                self.redirect('/blog/%s' % str(int(blog_id)))
        else:
            self.redirect("/login")

#Delete post
#Path: '/blog/delete/post#'
class DeletePost(Handler):
    def get(self, blog_id):
        logged_in = check_if_logged_in(self)
        if logged_in:
            key = ndb.Key('Post_class', int(blog_id))
            post = key.get()
            subject = post.subject
            blog = post.content

            if str(get_User_obj(self).username_obj) == post.author:
                #Delete Post
                key = ndb.Key('Post_class', int(blog_id))
                key.delete()
                self.redirect('/blog')
            else:
                #Re-render post with error
                self.redirect('/blog/%s?err=%s' % (int(post.key.id()),"editdelete"))

#Write a new comment
#Path: '/blog/post#/newcomment'
class NewComment(Handler):
    def get(self, blog_id):
        logged_in = check_if_logged_in(self)

        if logged_in == True:
            self.render("comment.html", edit_type="New Comment", logged_in = True)
        else:
            self.redirect("/login")

    def post(self, blog_id):
        post_id = str(int(blog_id))
        comment = self.request.get("comment")
        author = str(get_User_obj(self).username_obj)

        if comment:
            p = Comment_class(post_id=post_id, comment=comment, author=author)
            p.put()
            self.redirect('/blog/%s' % post_id)

        else:
            blog_err = "Please don't submit an empty comment!"
            self.render("comment.html", edit_type="New Post", content=content, blog_err=blog_err)

#Edit comment
#Path: '/blog/post#/comment#/editcomment'
class EditComment(Handler):
    def get(self, blog_id, post_id):
        #Check if user is logged in
        logged_in = check_if_logged_in(self)

        if logged_in == True:
            #Check if logged-in user is author of the comment
            key = ndb.Key('Comment_class', int(post_id))
            comment = key.get()
            loggedin_user = str(get_User_obj(self).username_obj)
            if loggedin_user == comment.author:
                self.render("comment.html", edit_type="Edit Comment", logged_in = True,
                    blog_id=str(int(blog_id)), comment=comment.comment,
                    redirect_url='/blog/%s' % str(int(blog_id)))
            else:
                #Re-render post with error
                self.redirect('/blog/%s?err=%s' % (str(int(blog_id)),"editdelete_cmt"))
        else:
            self.redirect("/login")

    def post(self, blog_id, post_id):
        key = ndb.Key('Comment_class', int(post_id))
        comment = key.get()
        comment.comment = self.request.get("comment")
        comment.put()
        self.redirect('/blog/%s' % str(int(blog_id)))

#Delete Comment:
#Path: '/blog/post#/comment#/deletecomment'
class DeleteComment(Handler):
    def get(self, blog_id, post_id):
        #Check if user is logged in
        logged_in = check_if_logged_in(self)

        if logged_in == True:
            #Check if logged-in user is author of the comment
            key = ndb.Key('Comment_class', int(post_id))
            comment = key.get()
            loggedin_user = str(get_User_obj(self).username_obj)
            if loggedin_user == comment.author:
                #Delete Post
                key.delete()
                self.redirect('/blog/%s' % str(int(blog_id)))
            else:
                #Re-render post with error
                self.redirect('/blog/%s?err=%s' % (str(int(blog_id)),"editdelete_cmt"))
        else:
            self.redirect("/login")

#Signup as a new user
class SignupHandler(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        user = self.request.get("username")
        pw = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        pw_re = re.compile(r"^.{3,20}$")
        em_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")

        user_err = ""
        pw_err = ""
        verify_err = ""
        email_err = ""

        if not user or not pw == verify or not pw:

            if not user or not user_re.match(user):
                user_err = "That's not a valid username."
            if not pw == verify and pw:
                verify_err = "The passwords do not match."
            if not pw or not pw_re.match(pw):
                pw_err = "That's not a valid password."
            if not em_re.match(email):
                email_err = "That's not a valid email."
            self.render("signup.html",user_err = user_err,verify_err = verify_err,pw_err = pw_err,email_err = email_err,
                user = user,email = email)
        else:
            q = User_class.query()
            q = q.filter(User_class.username_obj == user)
            q = q.get()

            if q:
                user_err = "That username already exists!"
                self.render("signup.html",user_err = user_err,verify_err = verify_err,pw_err = pw_err,email_err = email_err,
                    user = user,email = email)
            else:
                pw_hash = make_pw_hash(user, pw)
                pw_hash_trim = pw_hash.split('|')[0]

                u = User_class(username_obj = user, password_obj = pw_hash, email_obj = email)
                u.put()
                user_id = u.key.id()

                cookie = str('%s|%s' % (user_id, pw_hash_trim))

                self.response.headers.add_header('Set-Cookie',str("user_id=%s; Path=/" % cookie))
                self.redirect('/welcome')

#Login with user account
class LoginHandler(Handler):

    def get(self):
        self.render("login.html")

    def post(self):
        user = self.request.get("username")
        pw = self.request.get("password")

        login_err = ""

        q = User_class.query()
        q = q.filter(User_class.username_obj == user)
        q = q.get()

        if not q:
            user_err = "Invalid login"
            self.render("login.html",login_err = login_err, user = user)
        else:
            pw_hash = make_pw_hash(user, pw)
            pw_hash_trim = pw_hash.split('|')[0]

            u = User_class(username_obj = user, password_obj = pw_hash)
            u.put()
            user_id = u.key.id()

            cookie = str('%s|%s' % (user_id, pw_hash_trim))

            self.response.headers.add_header('Set-Cookie',str("user_id=%s; Path=/" % cookie))
            self.redirect('/welcome')

#Logout
class LogoutHandler(Handler):
    def get(self):
        self.response.delete_cookie('user_id')
        self.redirect('/login')

#Sign Up and Login Landing Page
class WelcomeHandler(Handler):
    def get(self):
        u = get_User_obj(self)
        self.render("success.html", user = u.username_obj)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog', MainHandler),
    ('/blog/newpost', PostHandler),
    ('/blog/([0-9]+)', PostRender),
    ('/blog/([0-9]+)/like', LikePost),
    ('/blog/([0-9]+)/unlike', UnlikePost),
    ('/blog/([0-9]+)/newcomment', NewComment),
    ('/blog/([0-9]+)/([0-9]+)/editcomment', EditComment),
    ('/blog/([0-9]+)/([0-9]+)/deletecomment', DeleteComment),
    ('/blog/edit/([0-9]+)', EditPost),
    ('/blog/delete/([0-9]+)', DeletePost),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
