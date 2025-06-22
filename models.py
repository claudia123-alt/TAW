from peewee import *

db = SqliteDatabase("db_projeto.db")

class BaseModel(Model):
    class Meta:
        database = db

class User(BaseModel):
    UserID = AutoField()
    Email = TextField(null=False)
    Password = TextField(null=False)
    is_admin = IntegerField(default=0)
    Name = TextField(null=False)
    class Meta:
        table_name = 'users'

class Student(BaseModel):
    StudentID = AutoField()
    Name = TextField(null=False)
    Email = TextField(null=False)
    Password = TextField(null=False)
    class Meta:
        table_name = 'student'

class Class(BaseModel):
    ClassID = AutoField()
    UserID = ForeignKeyField(User, backref="classes")
    Title = TextField(null=False)
    ClassDate = TextField(null=True)
    ClassTime = TextField(null=True)
    class Meta:
        table_name = 'class'

class Attendance(BaseModel):
    AttendanceID = AutoField()
    ClassID = ForeignKeyField(Class, backref="attendances")
    StudentID = ForeignKeyField(Student, backref="attendances")
    attend = IntegerField(default=0)
    class Meta:
        table_name = 'attendence'