#!/usr/bin/env python3
"""
Password hashing and validation module
"""

import bcrypt

def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt and returns the hashed password as a byte string.
    
    Arguments:
    password -- the password to hash
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against a given hashed password.
    
    Arguments:
    hashed_password -- the hashed password to validate against
    password -- the password to validate
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
