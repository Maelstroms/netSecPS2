#expected command line call
#for encryption
#python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file
#for decryption
#python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file
#hmac message authentication
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import argparse
import sys
from functools import partial
import __future__

backend = default_backend()

#argparse library to handle arguments
def arguments(arglist):
  parser = argparse.ArgumentParser(description='encryption and decryption protocol')
  parser.add_argument('-e', dest='encrypt', action='store_true', help='encrypt message')
  parser.add_argument('-d', dest='decrypt', action='store_true', help='decrypt message')
  # parser.add_argument('destination_key_filename')
  # parser.add_argument('sender_key_filename')
  # parser.add_argument('input_file')
  # parser.add_argument('output_file')
  return parser.parse_args(arglist)

def main(args):
  #encryption flag is set,
  if args.encrypt:
    print("encryption")
    #cypher key
    key = os.urandom(32)
    #CBC initiation vector
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    inPlainfile= open('input_plain_text.txt', 'r+')
    outCypherfile= open('cypherText.txt', 'r+')
    outPlainFile = open('output_plain_text.txt', 'r+')
    for chunk in iter(partial(inPlainfile.read, 1024), ''):
      cypherText = encryptor.update(chunk)
      outCypherfile.write(cypherText)
    ct = encryptor.update(b"a secret message") + encryptor.finalize()


    print"""break break break break break break break break break \n\n
break break break break break break break break break \n\n
break break break break break break break break break \n\n
break break break break break break break break break \n\n
=============================================================="""

    decryptor = cipher.decryptor()
    outCypherfile.seek(0)
    for chunk in iter(partial(outCypherfile.read, 1024), ''):
      plainText = decryptor.update(chunk)
      outPlainFile.write(plainText)
    print(decryptor.update(ct) + decryptor.finalize())
    # outPlainFile.seek(0)
    # for line in outPlainFile:
    #   print(line)


    inPlainfile.close()
    outCypherfile.close()
    outPlainFile.close()

  #decription flag set
  elif args.decrypt:
    print("decryption")
    print("encryption")
    inCypherFile = open(args.input_file, 'r')

    outPlainFile = open(args.output_file, 'w')

    for line in outPlainFile:
      print line
    inCypherFile.close()
    outPlainFile.close()

  else:
    print("oops")




if __name__ == "__main__":

  main(arguments(sys.argv[1:]))
