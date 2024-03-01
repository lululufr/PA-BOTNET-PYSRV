# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.generator import blueprint
from flask import render_template, request
from flask_login import login_required
from jinja2 import TemplateNotFound
import threading




@blueprint.route('/generator/gen',methods=['GET', 'POST'])
def gen_gen():
    return render_template('home/generator/generator-gen.html', segment='generator')

@blueprint.route('/generator/modify',methods=['GET', 'POST'])
def gen_modify():
    return render_template('home/generator/generator-modify.html', segment='generator')

