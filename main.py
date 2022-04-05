import flask
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from functools import wraps
from flask_ckeditor import CKEditorField

## CONFIGURE APP
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

## CONFIGURE LOGIN MANAGER
lg = LoginManager(app)
@lg.user_loader
def load_user(user_id):
    return User.query.get(user_id)

##
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
class User(UserMixin,db.Model):
    # __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key= True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    posts = db.relationship('BlogPost', backref='author')
    comments = db.relationship('Comment', backref='author')

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comments = db.relationship('Comment', backref='post')

class Comment(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    post_id= db.Column(db.Integer, db.ForeignKey('blog_posts.id') )
    author_id = db.Column(db.Integer, db.ForeignKey('user.id') )

db.create_all()

## CONFIGURE FORMS
class RegisterForm(FlaskForm):
    name = StringField(label='Username', validators=[DataRequired()])
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Register Now!')

class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Login')

class CommentForm(FlaskForm):
    comment = CKEditorField(label='Comment', validators=[DataRequired()])
    submit = SubmitField(label="Submit Comment")


## Defining a decorator for routes
def admin_only(function):
    """ renders 401 Error when decorated route gets somehow accessed without authorization"""
    @wraps(function)
    def wrapper(*args,**kwargs):
        is_admin = True if current_user.id == 1 else False
        if not is_admin :
            return flask.abort(401)
        else:
            return function(*args,**kwargs)  # calling function to see what it would normally return, and then returning it

    return wrapper  # this is what admin_only returns , so it should be our newly defined wrapper


### DEFINE ROUTES
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    is_admin = False
    try :
        if current_user.id == 1 :
            ## it's admin
            is_admin = True
    except AttributeError:
        pass
    is_logged = current_user.is_authenticated
    return render_template("index.html", all_posts=posts, is_admin=is_admin, logged=is_logged)


@app.route('/register', methods=['POST','GET'])
def register():

    is_logged = current_user.is_authenticated
    if is_logged :
        # print("already logged in")
        flash("You are currently logged in, logout first if you want to register a new account !")
        return redirect( url_for('get_all_posts') )


    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        raw_pw = form.password.data

        possible_user = User.query.filter_by(email=email).first()
        if possible_user:
            flash("User Exists")
            return redirect( url_for('register', email=email) )


        hashed_salted_pw = generate_password_hash(raw_pw,method='pbkdf2:sha256', salt_length=8)

        new_user = User(name=name,email=email,password=hashed_salted_pw)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect( url_for('get_all_posts') )



    return render_template("register.html", form=form)


@app.route('/login', methods=["POST","GET"] )
def login():
    is_logged = current_user.is_authenticated
    if is_logged :
        # print("already logged in")
        flash("You are already logged in !")
        return redirect( url_for('get_all_posts') )

    email_to_fill = request.args.get('email_to_fill')
    # print(email_to_fill)
    if email_to_fill is not None:
        form = LoginForm(email=email_to_fill)
    else:
        form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        provided_raw_password = form.password.data

        ## trying to find a user with this email on our website
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("This Email is not registered on our Website, Try again!")
            return redirect( url_for('login') )

        if not check_password_hash(user.password,provided_raw_password):
            flash("Wrong Password, Try again!")
            return redirect( url_for('login', email_to_fill=email) )
        else:
            # print('correct password')
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect( url_for('get_all_posts') )


@app.route("/post/<int:post_id>", methods=["GET", "POST"]   )
def show_post(post_id):
    form = CommentForm()

    if form.validate_on_submit():
        comment = form.comment.data
        author = current_user.id

        new_comment = Comment(comment=comment, author_id=author, post_id=post_id)
        db.session.add(new_comment)
        db.session.commit()


    is_admin = False
    try :
        if current_user.id == 1 :
            ## it's admin
            is_admin = True
    except AttributeError:
        pass
    requested_post = BlogPost.query.get(post_id)
    is_logged = current_user.is_authenticated
    return render_template("post.html", post=requested_post, is_logged=is_logged, is_admin=is_admin, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET","POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    #deleting the comments for that post
    comments = Comment.query.filter_by(post_id=post_id).all()
    for comment in comments :
        db.session.delete(comment)
    # and then deleting the post itself
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

## RUNNING THE APP
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)

