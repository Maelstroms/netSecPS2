#expected command line call
#for encryption
#python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file
#python fcrypt.py -e receiverPublicKey.pem senderPrivateKey.pem input_plain_text.txt cipherText.txt
#for decryption
#python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file
#python fcrypt.py -d receiverPrivateKey.pem senderPublicKey.pem cipherText.txt output_plain_text.txt
#hmac message authentication
# message should be in json format
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import argparse
import sys
from functools import partial
import json
import ast
import __future__

backend = default_backend()

#argparse library to handle arguments
def arguments(arglist):
  parser = argparse.ArgumentParser(description='encryption and decryption protocol')
  parser.add_argument('-e', dest='encrypt', action='store_true', help='encrypt message')
  parser.add_argument('-d', dest='decrypt', action='store_true', help='decrypt message')
  parser.add_argument('destination_key_filename')
  parser.add_argument('sender_key_filename')
  parser.add_argument('input_file')
  parser.add_argument('output_file')
  return parser.parse_args(arglist)

def main(args):
  #encryption flag is set
  #remember to encrypt with receiver public key
  if args.encrypt:
    print("encryption")
    #RSA key testing
    inPlainfile= open(args.input_file, 'r+b')
    outCipherfile= open(args.output_file, 'r+b')

    # for line in inPlainfile:
    #   if next(inPlainfile,'') == '':
    #     print "it works"
    #   else:
    #     continue

    with open(args.sender_key_filename, "rb") as key_file:
      private_key = serialization.load_pem_private_key(
      key_file.read(),
      password=None,
      backend=default_backend())

    with open(args.destination_key_filename, "rb") as key_file:
      public_key = serialization.load_pem_public_key(
      key_file.read(),
      backend=default_backend())

    #sender signing
    signer = private_key.signer(
    padding.PSS(
      mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH),
      hashes.SHA256())


    #begin symetric encryption
    # cipher key
    key = os.urandom(32)
    #CBC initiation vector
    iv = os.urandom(16)

     #key goes here in the message slot
    cipherKey = public_key.encrypt(key, padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA1()),
         algorithm=hashes.SHA1(),
         label=None))

    signer.update(cipherKey)
    signature = signer.finalize()
    outgoingPackage = {}
    outgoingPackage["signature"] = str(signature)
    outgoingPackage["key"] = str(cipherKey)
    outgoingPackage["IV"] = str(iv)

    outCipherfile.write(str(outgoingPackage)+"\n")

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    # cipher2 = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    # decryptor = cipher2.decryptor()


    inPlainfile.seek(0)
    for chunk in iter(partial(inPlainfile.read, 1024), ''):
      cipherText = encryptor.update(chunk)
      outCipherfile.write(cipherText)
    ct = '' + encryptor.finalize()
    outCipherfile.write(ct)

    outCipherfile.close()
    inPlainfile.close()


  #decription flag set
  elif args.decrypt:
    print("decryption")

    #RSA Verification
    inCipherfile = open(args.input_file, 'r+b')
    outPlainFile = open(args.output_file, 'r+b')

    with open(args.destination_key_filename, "rb") as key_file:
      private_key = serialization.load_pem_private_key(
      key_file.read(),
      password=None,
      backend=default_backend())

    with open(args.sender_key_filename, "rb") as key_file:
      public_key = serialization.load_pem_public_key(
      key_file.read(),
      backend=default_backend())


    textOut = ast.literal_eval(inCipherfile.readline())
    signature = textOut["signature"]
    decrypKey = textOut["key"]
    iv = textOut["IV"]


    verifier = public_key.verifier(signature,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    #signature verification
    verifier.update(decrypKey)
    verifier.verify()

    #RSA decryption of key
    key = private_key.decrypt(
     decrypKey,
     padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA1()),
         algorithm=hashes.SHA1(),
         label=None))


    #begin symetric decryption
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    decryptor = cipher.decryptor()
    for chunk in iter(partial(inCipherfile.read, 1024), ''):
      if chunk == '':
        outPlainFile.write(decryptor.update(chunk) + decryptor.finalize())
        break
      plainText = decryptor.update(chunk)
      outPlainFile.write(plainText)
    outPlainFile.seek(0)
    for line in outPlainFile:
      print(line)

    inCipherfile.close()
    outPlainFile.close()







  else:
    print("oops")




if __name__ == "__main__":

  main(arguments(sys.argv[1:]))
