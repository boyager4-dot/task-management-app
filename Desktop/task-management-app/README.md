# Task Management App

ระบบมอบหมายงานสำหรับออฟฟิศ — มอบหมายงานให้บุคคลหรือทั้งแผนก, รับงานจากกองกลางแผนกได้พร้อมกันหลายคน, ติดตามสถานะ, และดาวน์โหลดไฟล์ปฏิทิน (.ics) เมื่อรับงาน

## Features
- ล็อกอินด้วย username/password ต่อพนักงาน
- แผนก (เช่น บัญชี, Admin) — เพิ่มแผนกใหม่ได้จากหน้า Admin
- มอบหมายงานแบบรายบุคคล หรือทั้งแผนก
- พนักงานในแผนกกดรับงานกองกลางได้พร้อมกันหลายคน โดยแต่ละคนมีสถานะของตัวเอง
- อัปเดตสถานะงาน: รอดำเนินการ / กำลังทำ / เสร็จสิ้น
- ดาวน์โหลดไฟล์ .ics เพื่อเพิ่มงานเข้าปฏิทิน (Google Calendar / Outlook / Apple Calendar)
- หน้า Admin สำหรับเพิ่มแผนกและพนักงานใหม่

## Setup (local, VS Code)

```bash
# 1. สร้าง virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

# 2. ติดตั้ง dependencies
pip install -r requirements.txt

# 3. สร้างฐานข้อมูล + บัญชี admin เริ่มต้น
python seed.py

# 4. รันแอป
python app.py
```

เปิดเบราว์เซอร์ไปที่ `http://127.0.0.1:5000`

**บัญชี Admin เริ่มต้น:** username `admin` / password `admin1234`
(แนะนำให้เพิ่มพนักงานคนอื่นแล้วเปลี่ยนรหัสผ่าน admin ทันทีที่ใช้งานจริง)

## โครงสร้างโปรเจกต์
```
task-management-app/
├── app.py              # Flask routes ทั้งหมด
├── models.py           # โมเดลฐานข้อมูล (Department, Employee, Task, TaskAcceptance)
├── seed.py             # สร้าง DB + admin เริ่มต้น
├── requirements.txt
├── templates/          # หน้าเว็บ (Jinja2 + Tailwind CDN)
└── instance/app.db     # ไฟล์ฐานข้อมูล SQLite (สร้างอัตโนมัติ)
```

## Deploy ขึ้น Render
1. Push โปรเจกต์นี้ขึ้น GitHub
2. สร้าง Web Service ใหม่ใน Render จาก repo นี้
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. เพิ่ม `gunicorn` ใน requirements.txt และตั้ง environment variable `SECRET_KEY`
6. รัน `python seed.py` ผ่าน Render Shell ครั้งแรกเพื่อสร้าง DB และ admin

## ยังไม่รวมไว้ (พัฒนาต่อได้)
- ระบบแจ้งเตือนแบบ real-time (เช่น email/LINE Notify)
- การแก้ไข/ลบงานหลังสร้างแล้ว
- Sync กับ Google Calendar โดยตรงผ่าน API (ตอนนี้ใช้ไฟล์ .ics ให้กดเพิ่มเอง)
- สิทธิ์ระดับหัวหน้าแผนก (ตอนนี้มีแค่ Admin กับพนักงานทั่วไป)
