from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class Department(db.Model):
    __tablename__ = "departments"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    employees = db.relationship("Employee", backref="department", lazy=True)

    def __repr__(self):
        return f"<Department {self.name}>"


class Employee(UserMixin, db.Model):
    __tablename__ = "employees"
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id"), nullable=True)

    created_tasks = db.relationship(
        "Task", backref="creator", lazy=True, foreign_keys="Task.created_by_id"
    )
    assigned_tasks = db.relationship(
        "Task", backref="assignee", lazy=True, foreign_keys="Task.assigned_employee_id"
    )

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    def __repr__(self):
        return f"<Employee {self.username}>"


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    due_time = db.Column(db.Time, nullable=True)
    notes = db.Column(db.Text, nullable=True)  # "other" field
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Who created the task
    created_by_id = db.Column(db.Integer, db.ForeignKey("employees.id"), nullable=False)

    # Assignment: EITHER a single employee OR a whole department (never both)
    assigned_employee_id = db.Column(db.Integer, db.ForeignKey("employees.id"), nullable=True)
    assigned_department_id = db.Column(db.Integer, db.ForeignKey("departments.id"), nullable=True)
    assigned_department = db.relationship("Department", foreign_keys=[assigned_department_id])

    # Status for individually-assigned tasks. Department tasks track status
    # per-acceptance instead (see TaskAcceptance.status).
    status = db.Column(db.String(20), default="pending")  # pending / in_progress / done

    acceptances = db.relationship(
        "TaskAcceptance", backref="task", lazy=True, cascade="all, delete-orphan"
    )

    @property
    def assignment_type(self):
        return "department" if self.assigned_department_id else "individual"

    def __repr__(self):
        return f"<Task {self.title}>"


class TaskAcceptance(db.Model):
    """Records that one employee accepted a department-wide task.
    Multiple employees can each have their own row for the same task,
    which is how several people can pick up the same department task
    at once and track their own progress independently."""

    __tablename__ = "task_acceptances"
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("tasks.id"), nullable=False)
    employee_id = db.Column(db.Integer, db.ForeignKey("employees.id"), nullable=False)
    accepted_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="in_progress")  # in_progress / done

    employee = db.relationship("Employee")

    __table_args__ = (
        db.UniqueConstraint("task_id", "employee_id", name="uq_task_employee"),
    )
