from app.passwords.hashing import hash_password

# stały koszt weryfikacji przy nieistniejącym loginie
DUMMY_PASSWORD_HASH = hash_password("__timing_dummy_not_a_user_secret__")
