import os
from datetime import datetime, date, time as dtime

from flask import (
    Flask, render_template, redirect, url_for, request, flash, abort, Response
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)

from models import db, Department, Employee, Task, TaskAcceptance

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    
    instance_dir = os.path.join(BASE_DIR, 'instance')
    if not os.path.exists(instance_dir):
        os.makedirs(instance_dir)

    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(instance_dir, 'app.db')}"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.login_message = "กรุณาเข้าสู่ระบบก่อนใช้งาน"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(Employee, int(user_id))

    with app.app_context():
        db.create_all()
        if not Employee.query.first():
            admin_dept = Department.query.filter_by(name="Admin").first()
            if not admin_dept:
                admin_dept = Department(name="Admin")
                db.session.add(admin_dept)
                db.session.commit()
            
            admin_user = Employee(
                full_name="ผู้ดูแลระบบ",
                username="admin",
                department_id=admin_dept.id,
                is_admin=True
            )
            admin_user.set_password("1234")
            db.session.add(admin_user)
            db.session.commit()

    # ---------- Auth ----------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = Employee.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for("dashboard"))
            flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง", "error")
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    # ---------- Dashboard ----------
    @app.route("/")
    @login_required
    def dashboard():
        my_direct_tasks = Task.query.filter_by(
            assigned_employee_id=current_user.id
        ).order_by(Task.due_date.asc().nullslast()).all()

        dept_open_tasks = []
        if current_user.department_id:
            already_accepted_ids = {
                a.task_id for a in TaskAcceptance.query.filter_by(
                    employee_id=current_user.id
                ).all()
            }
            dept_open_tasks = [
                t for t in Task.query.filter_by(
                    assigned_department_id=current_user.department_id
                ).all()
                if t.id not in already_accepted_ids
            ]

        my_accepted = TaskAcceptance.query.filter_by(
            employee_id=current_user.id
        ).order_by(TaskAcceptance.accepted_at.desc()).all()

        created_by_me = Task.query.filter_by(
            created_by_id=current_user.id
        ).order_by(Task.created_at.desc()).all()

        return render_template(
            "dashboard.html",
            my_direct_tasks=my_direct_tasks,
            dept_open_tasks=dept_open_tasks,
            my_accepted=my_accepted,
            created_by_me=created_by_me,
        )

    # ---------- Task creation ----------
    @app.route("/tasks/create", methods=["GET", "POST"])
    @login_required
    def create_task():
        employees = Employee.query.order_by(Employee.full_name).all()
        departments = Department.query.order_by(Department.name).all()

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            notes = request.form.get("notes", "").strip()
            due_date_raw = request.form.get("due_date")
            due_time_raw = request.form.get("due_time")
            assign_type = request.form.get("assign_type")

            if not title:
                flash("กรุณากรอกชื่องาน", "error")
                return redirect(url_for("create_task"))

            due_date_val = date.fromisoformat(due_date_raw) if due_date_raw else None
            due_time_val = dtime.fromisoformat(due_time_raw) if due_time_raw else None

            task = Task(
                title=title,
                description=description,
                notes=notes,
                due_date=due_date_val,
                due_time=due_time_val,
                created_by_id=current_user.id,
            )

            if assign_type == "individual":
                emp_id = request.form.get("assigned_employee_id")
                if not emp_id:
                    flash("กรุณาเลือกผู้รับงาน", "error")
                    return redirect(url_for("create_task"))
                task.assigned_employee_id = int(emp_id)
            elif assign_type == "department":
                dept_id = request.form.get("assigned_department_id")
                if not dept_id:
                    flash("กรุณาเลือกแผนก", "error")
                    return redirect(url_for("create_task"))
                task.assigned_department_id = int(dept_id)
            else:
                flash("กรุณาเลือกวิธีมอบหมายงาน", "error")
                return redirect(url_for("create_task"))

            db.session.add(task)
            db.session.commit()
            flash("สร้างงานเรียบร้อยแล้ว", "success")
            return redirect(url_for("dashboard"))

        return render_template(
            "create_task.html", employees=employees, departments=departments
        )

    # ---------- Accept task ----------
    @app.route("/tasks/<int:task_id>/accept", methods=["POST"])
    @login_required
    def accept_task(task_id):
        task = db.session.get(Task, task_id) or abort(404)
        if task.assigned_department_id != current_user.department_id:
            abort(403)
        existing = TaskAcceptance.query.filter_by(
            task_id=task.id, employee_id=current_user.id
        ).first()
        if not existing:
            db.session.add(TaskAcceptance(task_id=task.id, employee_id=current_user.id))
            db.session.commit()
            flash("รับงานเรียบร้อยแล้ว งานถูกเพิ่มลงปฏิทินของคุณ", "success")
        return redirect(url_for("dashboard"))

    # ---------- Update status ----------
    @app.route("/tasks/<int:task_id>/status", methods=["POST"])
    @login_required
    def update_status(task_id):
        task = db.session.get(Task, task_id) or abort(404)
        new_status = request.form.get("status")
        if new_status not in ("pending", "in_progress", "done"):
            abort(400)

        if task.assigned_employee_id == current_user.id:
            task.status = new_status
            db.session.commit()
        else:
            acceptance = TaskAcceptance.query.filter_by(
                task_id=task.id, employee_id=current_user.id
            ).first()
            if not acceptance:
                abort(403)
            acceptance.status = new_status
            db.session.commit()

        flash("อัปเดตสถานะแล้ว", "success")
        return redirect(url_for("dashboard"))

    # ---------- Calendar (.ics) ----------
    @app.route("/tasks/<int:task_id>/calendar.ics")
    @login_required
    def task_ics(task_id):
        task = db.session.get(Task, task_id) or abort(404)
        d = task.due_date or date.today()
        t = task.due_time or dtime(9, 0)
        start = datetime.combine(d, t)
        end = start.replace(hour=min(start.hour + 1, 23))
        dtstamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

        def fmt(dt_):
            return dt_.strftime("%Y%m%dT%H%M%S")

        ics = (
            "BEGIN:VCALENDAR\r\n"
            "VERSION:2.0\r\n"
            "PRODID:-//Task Management App//TH\r\n"
            "BEGIN:VEVENT\r\n"
            f"UID:task-{task.id}@task-management-app\r\n"
            f"DTSTAMP:{dtstamp}\r\n"
            f"DTSTART:{fmt(start)}\r\n"
            f"DTEND:{fmt(end)}\r\n"
            f"SUMMARY:{task.title}\r\n"
            f"DESCRIPTION:{(task.description or '').replace(chr(10), ' ')}\r\n"
            "END:VEVENT\r\n"
            "END:VCALENDAR\r\n"
        )
        return Response(
            ics,
            mimetype="text/calendar",
            headers={
                "Content-Disposition": f"attachment; filename=task-{task.id}.ics"
            },
        )

    # ---------- Admin: departments ----------
    @app.route("/admin/departments", methods=["GET", "POST"])
    @login_required
    def admin_departments():
        if not current_user.is_admin:
            abort(403)
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            if name and not Department.query.filter_by(name=name).first():
                db.session.add(Department(name=name))
                db.session.commit()
                flash("เพิ่มแผนกเรียบร้อยแล้ว", "success")
            return redirect(url_for("admin_departments"))
        departments = Department.query.order_by(Department.name).all()
        return render_template("admin_departments.html", departments=departments)

    # ---------- Admin: delete department ----------
    @app.route("/admin/departments/<int:dept_id>/delete", methods=["POST"])
    @login_required
    def delete_department(dept_id):
        if not current_user.is_admin:
            abort(403)
        dept = db.session.get(Department, dept_id)
        if dept:
            # ป้องกันลบแผนกถ้ายังมีพนักงานอยู่
            if dept.employees:
                flash("ไม่สามารถลบแผนกนี้ได้เนื่องจากยังมีพนักงานสังกัดอยู่", "error")
            else:
                db.session.delete(dept)
                db.session.commit()
                flash("ลบแผนกเรียบร้อยแล้ว", "success")
        return redirect(url_for("admin_departments"))

    # ---------- Admin: employees ----------
    @app.route("/admin/employees", methods=["GET", "POST"])
    @login_required
    def admin_employees():
        if not current_user.is_admin:
            abort(403)
        departments = Department.query.order_by(Department.name).all()
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            department_id = request.form.get("department_id") or None
            is_admin = bool(request.form.get("is_admin"))

            if not (full_name and username and password):
                flash("กรุณากรอกข้อมูลให้ครบ", "error")
            elif Employee.query.filter_by(username=username).first():
                flash("มีชื่อผู้ใช้นี้อยู่แล้ว", "error")
            else:
                emp = Employee(
                    full_name=full_name,
                    username=username,
                    department_id=int(department_id) if department_id else None,
                    is_admin=is_admin,
                )
                emp.set_password(password)
                db.session.add(emp)
                db.session.commit()
                flash("เพิ่มพนักงานเรียบร้อยแล้ว", "success")
            return redirect(url_for("admin_employees"))

        employees = Employee.query.order_by(Employee.full_name).all()
        return render_template(
            "admin_employees.html", employees=employees, departments=departments
        )

    # ---------- Admin: delete employee ----------
    @app.route("/admin/employees/<int:emp_id>/delete", methods=["POST"])
    @login_required
    def delete_employee(emp_id):
        if not current_user.is_admin:
            abort(403)
        emp = db.session.get(Employee, emp_id)
        if emp:
            if emp.id == current_user.id:
                flash("ไม่สามารถลบบัญชีของตัวเองขณะใช้งานอยู่ได้", "error")
            else:
                db.session.delete(emp)
                db.session.commit()
                flash("ลบพนักงานเรียบร้อยแล้ว", "success")
        return redirect(url_for("admin_employees"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)