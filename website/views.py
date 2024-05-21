from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required,current_user

from website.auth import screen_locked_required

views= Blueprint("views",__name__)


@views.route('/')
@screen_locked_required  # Apply the decorator here
@login_required
def home():
    if current_user.is_authenticated:
        return render_template("home.html", user=current_user)
    else:
        return redirect(url_for('auth.login'))