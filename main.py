from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.app_context().push()


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "user_table"
    id = db.Column(db.Integer, primary_key=True)
    posts = relationship("BlogPost", back_populates="author")
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    name = db.Column(db.String(250), nullable=False)
    comments = relationship("Comments", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user_table.id'))
    author = relationship('User', back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comments", back_populates="parent_post")


class Comments(db.Model):
    __tablename__ = "comment_table"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user_table.id'))
    comment_author = relationship('User', back_populates='comments')
    text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates='comments')


gravatar = Gravatar(size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id == 1:
                return f(*args, **kwargs)
        return abort(403)

    return decorated_function


# Managing Routes
@app.route('/')
def get_all_posts():
    admin = False
    if current_user.is_authenticated:
        if current_user.id == 1:
            admin = True
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, admin=admin)


@app.route('/register', methods=['POST', 'GET'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if not User.query.filter_by(email=register_form.email.data).first():
            hashed_password = generate_password_hash(password=register_form.password.data,
                                                     method="pbkdf2:sha256",
                                                     salt_length=8)
            new_user = User()
            new_user.email = register_form.email.data
            new_user.name = register_form.name.data
            new_user.password = hashed_password
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('Your Email already has been registered')
            return redirect(url_for('login'))
    return render_template("register.html", form=register_form)


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        logged_in_user = User.query.filter_by(email=login_form.email.data).first()
        if logged_in_user:
            if check_password_hash(logged_in_user.password, login_form.password.data):
                login_user(logged_in_user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('The Entered Password Is Wrong')
                return redirect(url_for('login'))
        else:
            flash('The Entered Email Is Wrong')
            return redirect(url_for('login'))
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    comment_form = CommentForm()
    user = ""
    if current_user.is_authenticated:
        if current_user.id == 1:
            user = "admin"
        else:
            user = "user"
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        new_comment = Comments(text=comment_form.comment.data,
                               comment_author=current_user,
                               parent_post=requested_post)
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, user=user,
                           form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)

# host='0.0.0.0', port=5000
