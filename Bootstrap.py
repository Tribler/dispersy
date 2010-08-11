# from hashlib import sha1

# def bootstrap(database):
#     if __debug__:
#         from DispersyDatabase import DispersyDatabase
#     assert isinstance(database, DispersyDatabase)

#     users = [{"pem":buffer("""-----BEGIN RSA PRIVATE KEY-----
# Proc-Type: 4,ENCRYPTED
# DEK-Info: AES-128-CBC,E934AFE0A0CAA4985E709F67B4EB84E0

# zixsQtTEM7/V3zzHQWjJWbQf/Db4o4c6D9Jz8wbsLDYrz99rtZoKceAPucj667Fv
# kG6Vnufz9XtbEzRnevTzYwLc6LRs+Dly05W9rCsZX5y6vw00w+dmD7Q1QAhD++AM
# /GX7cqnoYjriDYE8pSiXxzfvt8rXU87MtWQeaetSm5+TB/G9ClYCsVNgNzpxuZX7
# D35LelEhoFv+uU5Pdc9L0TVwWaxigqAwTI4lzaoHtnjXm8WAT7uT4Cga31apeq6q
# LnkRMriOhggcwtvDtfklMwPN2FWhWqhiIbk3irHLJfk9SaCy6J8EgK2JwrRA0s8a
# T3m+qMZ4yH7+sF1WLr6H2dVcUsD0F1gGLvwrWZq5HHAta+vnlB+yF3OVzLgnz7Nw
# 70MUNM0h1iTz6Yx3TldBAc4VQuVljq2OqpqT9waFnt0=
# -----END RSA PRIVATE KEY-----
# """),
#               "host":u"mughal.tribler.org",
#               "port":6711},
#              {"pem":buffer("KAYAPO"),
#               "host":u"kayapo.tribler.org",
#               "port":1234},
#              {"pem":buffer("FRAYJA"),
#               "host":u"frayja.com",
#               "port":12345}]


#     for user in users:
#         database.execute(u"INSERT INTO user(mid, pem) VALUES(?, ?)",
#                          (buffer(sha1(user["pem"]).digest()), user["pem"]))
#         user_id = database.get_last_insert_rowid()

#         database.execute(u"INSERT INTO routing(user, host, port, time) VALUES(?, ?, ?, '0000-0-0 0:0:0')",
#                          (user_id, user["host"], user["port"]))
