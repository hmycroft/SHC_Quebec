import base64
import os
import sys
from pdf2image import convert_from_path
from pyzbar import pyzbar
from rich.console import Console
import zlib

# Set to false if you actually want to print the birthdate
REDACTBIRTHDATE = True
if len(sys.argv) == 2:
    pass
elif len(sys.argv) == 3:
    if sys.argv[2] == "False":
        REDACTBIRTHDATE = False
else:
    print(f"usage: {os.path.basename(__file__)} QR.pdf \[bool:REDACTBIRTHDATE]")
    exit()


# Extract QR from pdf file
iFileName = sys.argv[1]

# For pretty printing
console = Console(style="green on black", highlight=False)

images = convert_from_path(iFileName)
pilImage = images[0] # QR is on the first page, not handling multiple QRs in this proof of concept
decodedQR = pyzbar.decode(pilImage)
qr = decodedQR[0].data
console.print()
console.rule("[red]INFO CONTENUE DANS LE CODE QR", align="center", style="red", characters="\u2584")
console.print(f"[white on black]{qr.decode()}")

# Convert the numbers into text.
buff = ""
for i, cc in enumerate(qr[5:][::2]):
    buff += chr(int(qr[5:][i*2    :i*2 + 2]) + 45)

# Split the three parts from the text
rawHeader, rawPayload, rawSignature = buff.split(".")
console.print()
console.rule("[red]INFOS DÉCODÉES DU CODE QR ([bright_cyan on black]header[/] [blue on black]payload[/] [magenta on black]signature[/])", align="center", style="red", characters="\u2584")
console.print(f"[bright_cyan on black]{rawHeader}[/].[blue on black]{rawPayload}[/].[magenta on black]{rawSignature}")

header = eval(base64.urlsafe_b64decode(rawHeader.ljust(len(rawHeader)+len(rawHeader)%4, "=")))
payload = base64.urlsafe_b64decode(rawPayload.ljust(len(rawPayload)+len(rawPayload)%4, "="))
signature = base64.urlsafe_b64decode(rawSignature.ljust(len(rawSignature)+len(rawSignature)%4, "="))


# Validate and print the header
assert("kid" in header and "zip" in header and "alg" in header)
console.print()
console.rule("[red]HEADER DÉCODÉ", align="center", style="red", characters="\u2584")
console.print(f"kid: [white on black]{header['kid']}")
console.print(f"zip mode: [white on black]{header['zip']}")
console.print(f"algorithm: [white on black]{header['alg']}")


# Validate and print the payload
decompressed_payload = zlib.decompress(payload, -zlib.MAX_WBITS)
# some cleanup in entry for Python eval (the format is close enough to Python, but not quite 100%)
decompressed_payload = decompressed_payload.replace(b"false", b"False")
decompressed_payload = decompressed_payload.replace(b"true", b"True")
decompressed_payload = eval(decompressed_payload)
assert("iss" in decompressed_payload and "iat" in decompressed_payload and "vc" in decompressed_payload)
console.print()
console.rule("[red]PAYLOAD DÉCODÉ", align="center", style="red", characters="\u2584")


def printPayload(payload, tab="", enforceTab=False, newline = True):
    """Pretty print the payload. Otherwise, it's quite large with all the ({[]})..."""
    def printDict(dico):
        console.print()
        for key in dico:
            console.print(f"{tab}{key}: ", end="")
            printPayload(dico[key], tab + "   ")


    if isinstance(payload, (str, int, float)):
        if REDACTBIRTHDATE:
            try: # see if it's a birthdate... "redact" it if it is 
                if isinstance(payload, str):
                    year, month, day = payload.split("-")
                    int(year); int(month), int(day)
                    payload = "[/][red]" + "*"*len(year) + "[white]-[red]" + "*"*len(month) + "[white]-[red]" + "*"*len(day)
            except ValueError:
                pass
        console.print(f"{tab if enforceTab else ''}[white on black]{payload}")
    elif isinstance(payload, dict):
        printDict(payload)
    elif isinstance(payload, list):
        if len(payload) > 1 and not isinstance(payload[0], dict):
            enforceTab = True
            console.print()
        for item in payload:
            if isinstance(item, dict):
                printDict(item)
            elif isinstance(item, list):
                printPayload(item, tab + "   ", enforceTab)
            else:
                printPayload(item, tab + "   ", enforceTab)

printPayload(decompressed_payload)

console.print()
console.rule("[red]SIGNATURE DÉCODÉE (HEX)", align="center", style="red", characters="\u2584")
console.print(f"[white on black]{signature.hex()}")



# Public key is finally available at https://covid19.quebec.ca/PreuveVaccinaleApi/issuer/.well-known/jwks.json

# To turn off the deprecated warnings in jose
import warnings 
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from jose import jwk

hmacKey = {"kty":"EC","kid":"qFdl0tDZK9JAWP6g9_cAv57c3KWxMKwvxCrRVSzcxvM","use":"sig","alg":"ES256","crv":"P-256","x":"XSxuwW_VI_s6lAw6LAlL8N7REGzQd_zXeIVDHP_j_Do","y":"88-aI4WAEl4YmUpew40a9vq_w5OcFvsuaKMxJRLRLL0"}
key = jwk.construct(hmacKey)
if key.verify(f"{rawHeader}.{rawPayload}".encode(), signature) == True:
    console.rule("", characters="\u2584", style="bold green")
    console.rule("[bold green]SIGNATURE DU GOUVERNEMENT DU QUÉBEC VALIDE", characters="\u2584", style="bold green")
    console.rule("", characters="\u2584", style="bold green")
else:
    console.rule("", characters="\u2584", style="red")
    console.rule("[red]SIGNATURE INVALIDE!!!", characters="\u2584", style="red")
    console.rule("", characters="\u2584", style="red")





