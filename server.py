from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from fastapi import FastAPI, Request
from fastapi.responses import Response, JSONResponse


BLOCK = 16

class VulnerableServer:
    """
    Simula un servicio que:
    - encrypt(m) -> IV || C
    - decrypt(data) -> True/False según padding PKCS#7 (VULNERABLE)
    """

    def __init__(self):
        self.key = get_random_bytes(BLOCK)

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = get_random_bytes(BLOCK)
        padded = pad(plaintext, BLOCK)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        c = cipher.encrypt(padded)
        return iv + c  # IV || C

    def decrypt(self, data: bytes) -> bool:
        """
        Devuelve True si el padding es válido, False si no.
        """
        try:
            if len(data) < 2 * BLOCK or (len(data) % BLOCK != 0):
                return False

            blocks = [data[i:i+BLOCK] for i in range(0, len(data), BLOCK)]
            iv = blocks[0]
            cblocks = blocks[1:]

            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(b"".join(cblocks))

            _ = unpad(pt, BLOCK)  # lanza error si padding inválido
            return True

        except ValueError:
            return False

app = FastAPI()
server = VulnerableServer()

@app.post("/encrypt")
async def encrypt(request: Request):
    plaintext = await request.body()
    encrypted_data = server.encrypt(plaintext)
    return Response(content=encrypted_data, media_type="application/octec-stream")

@app.post("/decrypt")
async def decrypt(request: Request):
    data = await request.body()
    return JSONResponse({"status": server.decrypt(data)})






