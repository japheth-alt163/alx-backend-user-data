#!/usr/bin/env python3
"""
Definition of class BasicAuth
"""
import base64
from .auth import Auth
from typing import TypeVar

from models.user import User


class BasicAuth(Auth):
    """ Implements Basic Authorization protocol methods
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization header for Basic Authorization
        """
        if not authorization_header or not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header.split(" ")[-1]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str) -> str:
        """
        Decode a Base64-encoded string
        """
        if not base64_authorization_header or not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded = base64.b64decode(base64_authorization_header.encode('utf-8')).decode('utf-8')
            return decoded
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str) -> (str, str):
        """
        Returns user email and password from Base64 decoded value
        """
        if not decoded_base64_authorization_header or not isinstance(decoded_base64_authorization_header, str):
            return (None, None)

        if ':' not in decoded_base64_authorization_header:
            return (None, None)

        email, password = decoded_base64_authorization_header.split(":", 1)
        return (email, password)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Return a User instance based on email and password
        """
        if not user_email or not isinstance(user_email, str):
            return None
        if not user_pwd or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({"email": user_email})
            if not users:
                return None

            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
            return None
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Returns a User instance based on a received request
        """
        if not request:
            return None

        authorization_header = self.authorization_header(request)
        if not authorization_header:
            return None

        token = self.extract_base64_authorization_header(authorization_header)
        if not token:
            return None

        decoded = self.decode_base64_authorization_header(token)
        if not decoded:
            return None

        email, password = self.extract_user_credentials(decoded)
        if not email:
            return None

        return self.user_object_from_credentials(email, password)
