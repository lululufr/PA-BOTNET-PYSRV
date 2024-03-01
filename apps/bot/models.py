# -*- encoding: utf-8 -*-
from datetime import datetime

from apps import db

from apps.authentication.util import hash_pass



class Running(db.Model):

    __tablename__ = 'running'

    id = db.Column(db.Integer, primary_key=True)
    running = db.Column(db.INTEGER)


class Bots(db.Model):

    __tablename__ = 'victims'

    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.Integer, unique=True)
    group_id = db.Column(db.Integer, nullable=True)
    stealth = db.Column(db.Integer, nullable=True)
    multi_thread = db.Column(db.Integer, nullable=True)
    ip = db.Column(db.String(18), nullable=True)
    sym_key = db.Column(db.String(256), nullable=True)
    pub_key = db.Column(db.String(256), nullable=True)
    status = db.Column(db.INTEGER, default=0)
    #date_ajout = db.Column(db.Time, default=datetime.utcnow)

