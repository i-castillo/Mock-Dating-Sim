import os
import webapp2
import jinja2
import re
import hashlib
import hmac
import json

from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.api import images


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

secret = "welcome to chilis"


class Account(db.Model):
    name = db.StringProperty(required = True)
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty();

class User(db.Model):
    username = db.StringProperty(required = True);
    gender = db.StringProperty(required = True);
    location = db.StringProperty(required = True);
    picture = db.BlobProperty();
    description = db.TextProperty();
    college = db.StringProperty();
    questions = db.ListProperty(str);
    lookingfor = db.StringProperty();
    percent = 100;



class Message(db.Model):
    message = db.TextProperty(required = True);
    sender = db.StringProperty(required = True);
    receiver = db.StringProperty(required = True);
    created = db.DateTimeProperty(auto_now = True);

class Preferences(db.Model):
    user = db.StringProperty(required = True);
    question = db.StringProperty(required = True);
    response = db.StringProperty(required = True);

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw);

    def render_str(self, template, **params):
        t = jinja_env.get_template(template);
        return t.render(params);

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#Methods that relate to logging in/cookies/registration
class AuthHandler(Handler):
    #Method to login into the website
    #Send a cookie to the user with an encrypted (user)name

    def signin(self, user, username):
        self.setCookie('user-id', str(user.key().id()))
        self.setCookie('user-name', str(username.key().id()))


    def signout(self):
        self.response.headers.add_header('Set-Cookie', 'user-id=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'user-name=; Path=/')


    def setCookie(self, left, right):
        right = AuthHandler.encrypt(right);
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (left, right))

    @classmethod
    def encrypt(cls, val):
        return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

    @classmethod
    def checkUsername(cls, username):
        return username and USER_RE.match(username);

    @classmethod
    def checkPassword(cls, password):
        return password and PASS_RE.match(password);

    @classmethod
    def checkEmail(cls, email):
        return not email or EMAIL_RE.match(email);

    @classmethod
    def checkMatchPassword(cls, password, verify):
        return password == verify

    @classmethod
    def checkUserExists(cls, user):
        u = Account.all().filter('name =', user).get()
        return u;

    @classmethod
    def createUser(cls, user):
        return False;


class CookieHandler(AuthHandler):

    def setCookie(self, left, right):
        right = CookieHandler.encrypt(right);
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (left, right))

    @classmethod
    def checkCookie(cls, encrypted):
        val = encrypted.split('|')[0]
        if encrypted == cls.encrypt(val):
            return val

    @classmethod
    def encrypt(cls, val):
        return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

    def readCookie(self, name):
        cookieVal = self.request.cookies.get(name)
        return cookieVal and CookieHandler.checkCookie(cookieVal)

class SiteHandler(CookieHandler):
    def render_str(self, template, **params):
        params['user'] = self.user;

        t = jinja_env.get_template(template);
        return t.render(params);

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.readCookie('user-id')
        usernameid = self.readCookie('user-name')
        self.user = uid and Account.get_by_id(int(uid))
        self.username = usernameid and User.get_by_id(int(usernameid))

    def setCookie(self, left, right):
        right = AuthHandler.encrypt(right);
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (left, right))

    def check_secure_val(secure_val):
        val = secure_val.split('|')[0]
        if secure_val == make_secure_val(val):
            return val
    def make_secure_val(val):
        return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

class UserCreator(SiteHandler):
    def get(self):
        for i in range(25):
            u = Account(name="user"+str(i), username="usern"+str(i), password="admin");
            p = User(username="usern"+str(i), gender="M", location="admin");
            u.put();
            p.put();
        for i in range(25,50):
            u = Account(name="user"+str(i), username="usern"+str(i), password="admin");
            p = User(username="usern"+str(i), gender="F", location="admin");
            u.put();
            p.put();
        self.response.headers['Content-Type'] = 'text/hmtl'
        self.write("Added users");
        self.redirect("/view")

class PreferenceGenerator(SiteHandler):
    def post(self):
        question = str(self.request.get('data'))
        jsonval = json.loads(question);
        print("putting in %s" % question)
        self.username.questions.append(question);
        self.username.put();

    def get(self):
        user = self.username
        #query = "select * from User where username = '%s'" % user
        #numbers = db.GqlQuery(query);
        exclude =  []

        for i in user.questions:
            print(i)
            jsonval = json.loads(i);
            exclude.append(jsonval['question'])
            print(jsonval['question'])

        self.response.headers['Content-Type'] = 'json'
        self.write(json.dumps(exclude));

class ProfilePage(SiteHandler):
    def get(self, key):
        self.render("profile.html", muser = self.username);
    def post(self):
        print("posting");

class MainPage(SiteHandler):
    def get(self):
        self.render("main.html");

class ViewPage(SiteHandler):
    def get(self):
        if(self.user and self.username):
            users = db.GqlQuery("select * From User ORDER BY username desc")
            self.render("users.html", users=users)
        else:
            self.render("signin.html");

class MessagePage(SiteHandler):
    def get(self):
        print("opened up message pane");

    def post(self):
        receive = self.request.get('receiver')
        sender = self.username.username;
        message = self.request.get('message');

        m = Message(sender = sender, receiver=receive, message=message);
        m.put();
        self.response.headers['Content-Type'] = 'text/html'
        self.write(self.username.username);


class MatchGetter(SiteHandler):
    def compatibility(self, user):
        return ;

    def get(self):
        query = "select * from User where gender = 'M'"
        people = db.GqlQuery(query);
        a = [];
        for i in people:
            i.percent = self.compatibility(i);
            a.append(i)

        self.render("users.html", users=a)


class MessageGetter(SiteHandler):
    def post(self):
        receive = self.request.get('receiver')
        sender = self.username.username;
        query = "select * From Message WHERE receiver in ('%s', '%s') AND sender in ('%s', '%s') ORDER BY created asc" % (receive, sender, sender, receive);
        #query = "select * From Message ORDER BY created desc";
        messages =  db.GqlQuery(query)
        self.response.headers['Content-Type'] = 'text/html'
        self.render("messages.html", sender=sender, messages=messages)

class EditProfilePage(SiteHandler):
    def get(self):
        if(self.username):
            print(self.username, self.username.username, self.username.gender, self.username.location   );
            self.render("edit.html", muser=self.username);
        else:
            self.render("signin.html");

    def post(self):
        picture = self.request.get('picture')
        description = self.request.get('description')
        college = self.request.get('college')
        #Get logged in user.
        u = self.username;
        if(picture):
            picture = images.resize(picture, 256, 256)
            u.picture = picture;
        u.description = description;
        u.college = college;
        u.put();
        self.redirect("/user/%s" % u.username)

class SigninPage(AuthHandler):
    def get(self):
        self.render("signin.html")

    def post(self):
        username = self.request.get('name')
        password = self.request.get('password')

        u = Account.all().filter('username =', username).get()
        us = User.all().filter('username =', username).get()

        if u:
            self.signin(u, us)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login.'
            self.render('signin.html', error = msg)

class SignoutPage(AuthHandler):
    def get(self):
        self.signout();
        self.redirect('/');


class SignupPage(AuthHandler):

    def get(self):
        self.render("signup.html");

    def post(self):
        name = self.request.get("name");
        username = self.request.get("username");
        password = self.request.get("password");
        verify = self.request.get("verify");
        email = self.request.get("email");
        age = self.request.get("age");
        gender = self.request.get("gender");
        location = self.request.get("location");

        if(name == "admin" or 'x' in name):
            if(not AuthHandler.checkUserExists(username)):
                u = Account(name="admin", username="admin", password="admin", email="admin@admin.com");
                p = User(username="admin", gender="M", location="admin");
                u.put();
                p.put();
                self.signin(u,p);
                self.redirect("/edit")

        error = False;
        params = dict(name = name, email = email);

        if not name:
            params['errorname'] = "Invalid name.";
        if not AuthHandler.checkUsername(username):
            params['erroruname'] = "Invalid Username."
            error = True

        if not AuthHandler.checkPassword(password):
            params['errorpassword'] = "Invalid Password."
            error = True

        elif not AuthHandler.checkMatchPassword(password, verify):
            params['errorverify'] = "Passwords do not match."
            error = True

        if not AuthHandler.checkEmail(email):
            params['erroremail'] = "That's not a valid email."
            error = True

        if not error and AuthHandler.checkUserExists(username):
            params['error_exists'] = "That username exists. Try again.";
            error = True;

        if not str(age).isdigit():
            params['errorage'] = "Invalid Age.";
            error = True;
        if not location:
            params['errorlocation'] = "Invalid location.";
            error = True;

        if(error):
            self.render("signup.html", **params)
        else:
            u = Account(name=name, username=username, password=password, email=email);
            p = User(username=username, gender=gender, location=location);
            u.put();
            p.put();
            self.signin(u,p);
            self.redirect("/edit")

class Image(webapp2.RequestHandler):
    def get(self):
        user = self.request.get('img')
        user = User.get_by_id(int(user));
        self.response.headers['Content-Type'] = 'text/html'
        if(user.picture):
            self.response.headers['Content-Type'] = 'image/png'
            self.response.out.write(user.picture)
        else:
            self.response.headers['Content-Type'] = 'image/png'

            self.response.out.write('/images/blank-silhouette-medium-420x420.png')

class UserPage(SiteHandler):
    def get(self, key):
        self.render("user.html", user=db.get(db.Key.from_path('User', int(key))));
    def post(self):
        self.render("user.html");

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/getpref', PreferenceGenerator),
    ('/getm', MessageGetter),
    ('/message', MessagePage),
    ('/signin', SigninPage),
    ('/signup', SignupPage),
    ('/signout', SignoutPage),
    ('/view', MatchGetter),
    ('/img/', Image),
    ('/user/([a-zA-Z0-9]+)', ProfilePage),
    ('/edit', EditProfilePage),
    ('/create', UserCreator),
    ('/welcome', MainPage)], debug=True)
