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
import __future__

backend = default_backend()

#argparse library to handle arguments
def arguments(arglist):
  parser = argparse.ArgumentParser(description='encryption and decryption protocol')
  parser.add_argument('-e', dest='encrypt', action='store_true', help='encrypt message')
  parser.add_argument('-d', dest='decrypt', action='store_true', help='decrypt message')
  # parser.add_argument('destination_key_filename')
  # parser.add_argument('sender_key_filename')
  parser.add_argument('input_file')
  parser.add_argument('output_file')
  return parser.parse_args(arglist)

def main(args):
  #encryption flag is set,
  if args.encrypt:
    print("encryption")
    #cypher key
    key = os.urandom(32)
    print("key " + key + "\n")
    #CBC initiation vector
    iv = os.urandom(16)
    print("iv " + iv + "\n")
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    cipherString = ''
    inPlainFile = open(args.input_file, 'r+')
    outCypherFile = open(args.output_file, 'r+')
    # outCypherFile.write(key+"\n")
    # outCypherFile.write(iv+"\n")
    # for line in inPlainFile:
    #   cipherString = encryptor.update(line)
    #   outCypherFile.write(cipherString)
        #print line
    outCypherFile.write(encryptor.update(b"a secret message") + encryptor.finalize())
    print(outCypherFile.readline())
    inPlainFile.close()
    outCypherFile.close()

    # doubleCheck = open(args.output_file, 'r+')
    # for line in doubleCheck:
    #   print(line)

    #TODO DELETE symetric decryption test before RSA implementation
    inCypherFile = open(args.output_file, 'r+')
    outPlainFile = open('output_plain_text.txt' , 'r+')
    # for line in inCypherFile:
    #   print line
    #   outPlainFile.write(decryptor.update(line))
    outPlainFile.write(inCypherFile.readline() + decryptor.finalize())

    for line in outPlainFile:
      print line
    inCypherFile.close()
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
