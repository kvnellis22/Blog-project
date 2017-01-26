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

class Comment(db.Model):
    post_id = db.IntegerProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    created = db.DateTimeProperty(auto_now_add = True)
    user_id = db.IntegerProperty(required = True)
    comment= db.TextProperty(required = True)

    def getName(self):
        user = User.by_id(self.user_id)
        return user.name