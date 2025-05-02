from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()


def get_password_hash(plain_password: str):
    return password_hash.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str):
    return password_hash.verify(plain_password, hashed_password)
