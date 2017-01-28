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

class Like(db.Model):
    user_id = db.IntegerProperty(required = True)
    post_id = db.IntegerProperty(required =True)

    def getName(self):
        user = User.by_id(self.user_id)
        return user.name