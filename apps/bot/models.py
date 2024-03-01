# -*- encoding: utf-8 -*-
from datetime import datetime

from apps import db

from apps.authentication.util import hash_pass

class Bots(db.Model):

    __tablename__ = 'bots'

    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(64), unique=True)
    ip_prive = db.Column(db.String(18))
    ip_public = db.Column(db.String(18))
    statut = db.Column(db.String(50))
    #date_ajout = db.Column(db.Time, default=datetime.utcnow)

