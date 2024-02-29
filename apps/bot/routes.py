# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.bot import blueprint
from flask import render_template, request
from flask_login import login_required
from jinja2 import TemplateNotFound


@blueprint.route('/ok',methods=['GET', 'POST'])
def bot_managment():
    if request.method == 'GET':
        return "yaya"
    return "ok"
