"""Run once to create the database and an initial admin account.
Usage: python seed.py
"""
from app import app
from models import db, Department, Employee

with app.app_context():
    db.create_all()

    # Default departments requested: บัญชี (Accounting), Admin
    default_depts = ["บัญชี", "Admin"]
    for name in default_depts:
        if not Department.query.filter_by(name=name).first():
            db.session.add(Department(name=name))
    db.session.commit()

    admin_dept = Department.query.filter_by(name="Admin").first()

    if not Employee.query.filter_by(username="admin").first():
        admin = Employee(
            full_name="System Admin",
            username="admin",
            is_admin=True,
            department_id=admin_dept.id if admin_dept else None,
        )
        admin.set_password("admin1234")  # change this after first login!
        db.session.add(admin)
        db.session.commit()
        print("Created admin account -> username: admin / password: admin1234")
    else:
        print("Admin account already exists.")

    print("Database ready at instance/app.db")
