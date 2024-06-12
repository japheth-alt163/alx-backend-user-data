#!/usr/bin/env python3
"""Auth module for user authentication."""

from db import DB
import bcrypt
import uuid

class Auth:
    """Auth class to interact with the authentication database.

    This class provides methods for user registration, login, session management,
    and password reset functionalities. It interacts with the DB class to
    handle database operations.
    """

    def __init__(self):
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """Hashes a password with bcrypt.

        Args:
            password: The password to hash (string).

        Returns:
            The hashed password (bytes).
        """
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password_bytes, salt)

    def register_user(self, email: str, password: str) -> DB.User:
        """Registers a new user.

        Args:
            email: The user's email (string).
            password: The user's password (string).

        Raises:
            ValueError: If a user already exists with the passed email.

        Returns:
            The User object.
        """
        if self._db.get_user(email):
            raise ValueError(f"User {email} already exists")

        hashed_password = self._hash_password(password)
        user = self._db.add_user(email, hashed_password)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if the email and password combination is valid.

        Args:
            email: The user's email (string).
            password: The user's password (string).

        Returns:
            True if the email and password match, False otherwise.
        """
        user = self._db.get_user(email)
        if not user:
            return False
        password_bytes = password.encode('utf-8')
        hashed_password = user.hashed_password
        return bcrypt.checkpw(password_bytes, hashed_password)

    def _generate_uuid(self) -> str:
        """Generates a new UUID.

        Returns:
            A string representation of a new UUID.
        """
        return str(uuid.uuid4())

    def create_session(self, email: str) -> str:
        """Creates a new session for a user.

        Args:
            email: The user's email (string).

        Returns:
            The session ID (string) or None if the user is not found.
        """
        user = self._db.get_user(email)
        if not user:
            return None
        session_id = self._generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> DB.User:
        """Gets the user corresponding to a session ID.

        Args:
            session_id: The session ID (string).

        Returns:
            The User object or None if the session ID is invalid.
        """
        if not session_id:
            return None
        return self._db.get_user(session_id=session_id)

    def destroy_session(self, user_id: int) -> None:
        """Destroys a user's session.

        Args:
            user_id: The user's ID (integer).
        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset password token for a user.

        Args:
            email: The user's email (string).

        Raises:
            ValueError: If the user does not exist.

        Returns:
            The reset password token (string).
        """
        user = self._db.get_user(email)
        if not user:
            raise ValueError(f"User {email} not found")
        reset_token = self._generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_
