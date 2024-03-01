# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.api import blueprint
from flask import render_template, request
from flask_login import login_required
from jinja2 import TemplateNotFound
import threading

@blueprint.route('/api/<inc>')
def zombie():
    return render_template('home/bot/bot.html', segment='bot')

