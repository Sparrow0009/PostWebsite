from cryptography.fernet import Fernet
from flask import Blueprint, render_template, flash, url_for, redirect
from flask_limiter.util import get_remote_address
from flask_login import current_user, login_required
from flask_migrate import current
from unicodedata import category

from accounts.views import roles_required
from config import db, Post, logger, User
from posts.forms import PostForm
from sqlalchemy import desc

posts_bp = Blueprint('posts', __name__, template_folder = 'templates')


@posts_bp.route('/posts')
@login_required
@roles_required('end_user')
def posts():
    all_posts = Post.query.order_by(desc('id')).all()
    for post in all_posts:
        user = User.query.get(post.userid)
        cipher = Fernet(user.derive_key())
        post.title = cipher.decrypt(post.title).decode()
        post.body = cipher.decrypt(post.body).decode()
    return render_template('posts/posts.html', posts = all_posts)


@posts_bp.route('/create', methods = ('GET', 'POST'))
@login_required
@roles_required('end_user')
def create():

    form = PostForm()
    if form.validate_on_submit():
        user = User.query.get(current_user.get_id())
        cipher = Fernet(user.derive_key())
        encrypted_title = cipher.encrypt(form.title.data.encode())
        encrypted_body = cipher.encrypt(form.body.data.encode())
        new_post = Post(userid=current_user.get_id(), title=encrypted_title, body=encrypted_body)
        db.session.add(new_post)
        db.session.commit()
        logger.info('[User:{}, Role:{}, Post_ID:{}, IP:{}] Post Created'.format(current_user.email, current_user.role,new_post.userid, get_remote_address()))
        flash('Post Created', category = 'success')
        return redirect(url_for('posts.posts'))
    return render_template('posts/create.html', form=form)


@posts_bp.route('/<int:id>/update', methods = ('GET', 'POST'))
@login_required
@roles_required('end_user')
def update(id):
    post_to_update = Post.query.filter_by(id=id).first()
    if post_to_update.user.id != current_user.id:
        flash("You are not allowed to update posts of other users", category='danger')
        return redirect(url_for('posts.posts'))
    if not post_to_update:
        return redirect(url_for('posts.posts'))

    form = PostForm()
    if form.validate_on_submit():
        post_to_update.update(title=form.title.data, body=form.body.data)

        flash('Post Updated', category= 'success')
        return redirect(url_for('posts.posts'))
    form.title.data = post_to_update.title
    form.body.data = post_to_update.body
    logger.info('[User:{}, Role:{}, Post_ID:{}, Post_Author:{}, IP:{}] Post Updated'.format(current_user.email, current_user.role, post_to_update.userid, post_to_update.user.email, get_remote_address()))

    return render_template('posts/update.html', form=form)


@posts_bp.route('/<int:id>/delete')
@login_required
@roles_required('end_user')
def delete(id):
    post_to_delete = Post.query.filter_by(id=id).first()
    logger.info('[User:{}, Role:{}, Post_ID:{}, Post_Author:{}, IP:{}] Post Deleted'.format(current_user.email,
                                                                                            current_user.role, id,
                                                                                            post_to_delete.user.email,
                                                                                            get_remote_address()))
    db.session.delete(post_to_delete)
    db.session.commit()
    flash('Post Deleted', category = "success")
    return redirect(url_for('posts.posts'))