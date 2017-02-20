import hashlib
BLOCKSIZE = 65536
hasher = hashlib.sha256()
with open('prueba.pdf', 'rb') as afile:
    buf = afile.read(BLOCKSIZE)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(BLOCKSIZE)
print(hasher.hexdigest())
