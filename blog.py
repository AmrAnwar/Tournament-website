import os
import re
import random
import hashlib
import hmac
import math
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
  
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
   
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
   
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class HomeHandler(webapp2.RequestHandler):
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

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(HomeHandler):
 
  def get(self):
      self.redirect('/home')

##### user stuff
def make_salt(length = 5):
    
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
   
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
##### home stuff

def home_key(name = 'default'):
    return db.Key.from_path('homes', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    number =   db.StringProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
    @classmethod
    def by_id(cls, uid):
        return Post.get_by_id(uid, parent = home_key())
class Result(db.Model):
    name = db.StringProperty(required = True)
    item = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

#########################

def member_key(group = 'default'):
    return db.Key.from_path('members', group)

def result_key(group = 'default'):
    return db.Key.from_path('members', group)
class Member(db.Model):
    tour = db.StringProperty(required = True)
    name = db.StringProperty(required = True)
    level = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add = True)
    me_id = db.IntegerProperty(required=True)
    @classmethod
    def by_id(cls, uid):
        return Post.get_by_id(uid, parent = home_key())

##########################
class homeFront(HomeHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

class PostPage(HomeHandler):
    def get(self, post_id):       
        post= Post.by_id(int(post_id))
        if not post:
            self.error(404)
            return
        tour = post.subject
        members = db.GqlQuery("SELECT * FROM Member  WHERE tour = '%s' "%tour )
        items= Result.all().order('-created')

        x= len(list(members))
        
        if ( x==  int(post.number)):
            names= list()
            levels= list()
            for i in members:
                names.append(i.name)
                levels.append(i.level)
            r = int(math.log(x,2))
            self.render("tour_test.html",post=post,members=members,x=x,r=r,names=names,levels=levels,items=items)
        
        else :
            self.render("post_test.html", post = post,members=members,x=x)

    def post(self,post_id):
        if self.user:
            post= Post.by_id(int(post_id))
            tour=post.subject
            members = db.GqlQuery("SELECT * FROM Member  WHERE tour = '%s' "%tour )
            ##
            uid = self.read_secure_cookie('user_id')
            user = User.by_id(int(uid))
            name=user.name
            x= len(list(members))
            ##
            if(x < int (post.number)):

                test = db.GqlQuery("SELECT * FROM Member  WHERE tour = '%s' and name = '%s' "%(tour,name ))

                level=0
                me_id = int(uid)
                error=""
                flag= False
                
                for i in test:
                    if (user.name ==i.name):
                        flag=True
                      
                if ( flag ):
                    error=" !!! you  acually joined  777  !!! "

                else :
                    d = Member(parent = member_key(), tour = tour, name =  name,level= level,me_id= me_id)
                    d.put()
                members = db.GqlQuery("SELECT * FROM Member  WHERE tour = '%s' "%tour )
                x= len(list(members))
                r= int(post.number)-x
                self.render("post_test.html", post = post,members=members,x=x,r=r,error=error)
                #self.redirect('/%s'%post.key().id())
            else:
                item = self.request.get("result")
                if item:
                    a=Result(parent=result_key(),name = name ,item=item)
                    a.put()
                self.redirect('/home/%s'%post_id)


        else:
            self.redirect('/signup')   
class  update(HomeHandler):
        def get(self):
            tours =  db.GqlQuery("SELECT * FROM Post")
            members = db.GqlQuery("SELECT * FROM User")
            self.render("up.html",tours=tours,members=members)
        def post(self):
            t=self.request.get('tour')
            n=self.request.get('name')
            r=self.request.get('round')
            players = db.GqlQuery("SELECT * FROM Member  WHERE tour = '%s'  "%t )
            for m in players:
                if m.name==n:
                    #self.write(m.key().id())
                    obj = db.get(db.Key.from_path("Member", m.key().id(), parent=member_key()))
                    obj.level=int(r)
                    #self.write(obj.level)
                    obj.put()
                    break
            #self.redirect('/home')
class NewPost(HomeHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/home')

        subject = self.request.get('subject')
        content = self.request.get('content')
        number = self.request.get('number')
        if subject and content and number:
            p = Post(parent = home_key(), subject = subject, content = content,number=number)
            p.put()
            self.redirect('/home/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(HomeHandler):
    def get(self):
        self.render("signup-form.html")

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
            self.render('signup-form.html', **params)
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
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/home')

class Login(HomeHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/home')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(HomeHandler):
    def get(self):
        self.logout()
        self.redirect('/home')

class Unit3Welcome(HomeHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/home/?', homeFront),
                               ('/home/([0-9]+)', PostPage),
                               ('/home/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/home/up',update),
                               ],
                              debug=True)
