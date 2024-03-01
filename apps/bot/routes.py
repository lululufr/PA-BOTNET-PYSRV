# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.bot import blueprint
from flask import render_template, request
from flask_login import login_required
from jinja2 import TemplateNotFound
import threading

from action_botnet import launch
from apps.bot.models import Bots
from apps import db

@blueprint.route('/bot')
#@login_required
def bot_index():
    return render_template('home/bot/bot.html', segment='bot')

@blueprint.route('/bot/launch',methods=['GET', 'POST'])
def bot_launch():
        output = request.form.to_dict()
        name = output['name']
        try :
            if name is not int :
                return render_template('home/bot/bot.html', segment='bot', name=0)
            #launch.start_botnet(name)
            print("lancement")
        except :
            return render_template('home/bot/bot.html', segment='bot', name=0)

        return render_template('home/bot/bot.html', segment='bot', name=name)

@blueprint.route('/bot/list',methods=['GET', 'POST'])
def bot_list():
    bots_all = Bots.query.all()
    return render_template('home/bot/bot-list.html', segment='bot',bots=bots_all)

@blueprint.route('/bot/group',methods=['GET', 'POST'])
def bot_group():
    return render_template('home/bot/bot-group.html', segment='bot')

@blueprint.route('/bot/action',methods=['GET', 'POST'])
def bot_action():
    return render_template('home/bot/bot-action.html', segment='bot')

#bot manuel
@blueprint.route('/bot/add',methods=['GET', 'POST'])
def bot_add():
    if request.method == 'POST':
        output = request.form.to_dict()

        new_bot = Bots(nom=output['name'],ip_prive=output['ip_priv'],ip_public=output['ip_pub'], statut="ok")
        db.session.add(new_bot)
        db.session.commit()

    return render_template('home/bot/bot-add.html', segment='bot')
