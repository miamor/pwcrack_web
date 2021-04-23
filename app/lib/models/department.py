from app import db

class DepartmentModel(db.Model):
    __tablename__ = 'departments'
    id = db.Column(db.String(30), primary_key=True)
    name = db.Column(db.String(100), nullable=False, default='', index=True, unique=True)
    color = db.Column(db.String(7), nullable=True, default='')
