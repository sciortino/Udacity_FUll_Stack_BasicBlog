
from google.appengine.ext import ndb

# Post Model

class Post_class(ndb.Model):
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    author = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)

# Comment model

class Comment_class(ndb.Model):
    post_id = ndb.StringProperty(required=True)
    comment = ndb.TextProperty(required=True)
    author = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)

# User model

class User_class(ndb.Model):
    username_obj = ndb.StringProperty(required=True)
    password_obj = ndb.StringProperty(required=True)
    email_obj = ndb.StringProperty(required=False)
    created_obj = ndb.DateTimeProperty(auto_now_add=True)

# Likes model

class Likes_class(ndb.Model):
    post_id = ndb.StringProperty(required=True)
    username = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)