from app import db


class NodeModel(db.Model):
    __tablename__ = 'nodes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, default='', index=True, nullable=True)
    hostname = db.Column(db.String, default='', index=True, nullable=True)
    port = db.Column(db.Integer, default=9999, index=True, nullable=True)
    username = db.Column(db.String, default='', index=True, nullable=True)
    password = db.Column(db.String, default='', index=True, nullable=True)
    active = db.Column(db.Boolean, default=False, index=True, nullable=True)
    hashcat_binary = db.Column(db.String, default='', index=True, nullable=True)
    hashcat_rules_path = db.Column(db.String, default='', index=True, nullable=True)
    wordlists_path = db.Column(db.String, default='', index=True, nullable=True)
    uploaded_hashes_path = db.Column(db.String, default='', index=True, nullable=True)
    hashcat_status_interval = db.Column(db.Integer, default='', index=True, nullable=True)
    hashcat_force = db.Column(db.Integer, default='', index=True, nullable=True)

