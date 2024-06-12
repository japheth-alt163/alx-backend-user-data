#!/usr/bin/env python3
"""
Declare a SQLAlchemy model named 'User' corresponding to a
database table named "users"
"""
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker
import bcrypt

Base = declarative_base()

class User(Base):
    """
    Definition of class User
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)

    def set_password(self, password: str) -> None:
        """
        Hashes the password and stores the hashed password.
        """
        self.hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password: str) -> bool:
        """
        Checks if the provided password matches the stored hashed password.
        """
        return bcrypt.checkpw(password.encode('utf-8'), self.hashed_password.encode('utf-8'))

if __name__ == "__main__":
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    new_user = User(email="example@example.com")
    new_user.set_password("my_secure_password")
    session.add(new_user)
    session.commit()

    # Verify the password
    assert new_user.check_password("my_secure_password") is True
    assert new_user.check_password("wrong_password") is False

    # Printing table information
    print(User.__tablename__)
    for column in User.__table__.columns:
        print("{}: {}".format(column, column.type))
