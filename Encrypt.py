# Include the Dropbox SDK
import dropbox, base64, sys, os
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES

# Get your app key and secret from the Dropbox developer website
#app_key = 'ohwhc1fbzf6yx73'
#app_secret = 'gbd8gzvfsr1tsji'

client = dropbox.client.DropboxClient('JuRIi7UrmgAAAAAAAAAAR49QrHOL5WRm5Z5a84PFYkIDEd9PSeHqT0CDdYsRAY_g') #Log in to dropbox account
username = raw_input("What is your name? ") #find out which AES file to use

f = open(username+'.pem','r') #import correct keys
my_key = RSA.importKey(f.read())
f.close()

f = open(username+'public.pem', 'r')
myPubKey = RSA.importKey(f.read())
f.close

def keyGen(name): #generate and export matching public an private key

    key = RSA.generate(1024)

    f = open(name+'.pem','wb')
    f.write(key.exportKey())
    f.close()

    f = open(name+'public.pem', 'wb')
    f.write(key.publickey().exportKey())
    f.close

def getAESkey(id): #download AES key from dropbox and decrypt using RSA private key
    f, metadata = client.get_file_and_metadata(id+'AESkey.txt.enc')
    return RSADecrypt(f.read(), my_key)

def pad(message): #pad message so that it is the correct size for AES decryption
    return message + b"\0" * (AES.block_size - len(message) % AES.block_size)

def RSAEncrypt(message, key):
    return key.encrypt(message, 32)

def RSADecrypt(message, key):
    return key.decrypt(message)

def AESEncrypt(message, key):
    iv = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    return (iv + encryptor.encrypt(pad(message)))

def AESDecrypt(ciphertext, key):
    iv=ciphertext[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    plaintext = decryptor.decrypt(ciphertext[16:])
    return plaintext.rstrip(b"\0")

def encryptFile (filename, key, mode):
    p = open(filename, 'rb') #read plain text
    plaintext = p.read()
    p.close()
    ciphertext = ""
    c = open(filename[:-4]+"_Encrypted.enc", 'wb') #create file to write encrypted data to
    if mode == 0:
        ciphertext = RSAEncrypt(plaintext, key) #encrypt plaintext
        c.write(bytes(ciphertext[0]))      #write ciphertext
    else:
        ciphertext = AESEncrypt(plaintext, key)
        c.write(bytes(ciphertext)) #write ciphertext
    c.close()

def decryptFile (filename, key, mode):
    d = open(filename, 'rb')
    readCipherText = d.read() #read ciphertext
    d.close()
    decrypted=""
    if mode == 0:
        decrypted = RSADecrypt(readCipherText, key)
    else:
        decrypted = AESDecrypt(readCipherText, key)
    result = open("Decrypted_"+filename[:-4], 'wb') #create file to write decrypted text
    result.write(decrypted)
    result.close()

def uploadFile(filename):
    AESkey = getAESkey(username) #get the AES key from dropbox
    encryptFile(filename, AESkey, 1) #encrypt file using that key
    f = open(filename[:-4]+'_Encrypted.enc', 'rb')
    response = client.put_file(filename+'.enc', f) #upload file
    os.remove(filename[:-4]+'_Encrypted.enc')#delete encrypted file

def downloadFile(filename):
    AESkey = getAESkey(username)
    f, metadata = client.get_file_and_metadata(filename) #download file
    out = open(filename, 'wb')
    out.write(f.read()) #write encrypted data to file
    out.close()
    decryptFile(filename, AESkey, 1) #decrypt the file
    os.remove(filename)#delete encrypted file

def addUser(name):
    if not os.path.isfile(name+'public.pem'): #create new keys if they do not exist
        keyGen(name)

    f = open(name+'public.pem', 'r') #load their public key
    newPubKey = RSA.importKey(f.read())
    f.close()
    a = open('AESkey.txt', 'wb')
    a.write(getAESkey(username)) #write the unencrypted AES key for them
    a.close()
    encryptFile('AESkey.txt', newPubKey, 0)#encrypt AES key for them
    os.remove('AESkey.txt') #remove unencrypted AES key

    f=open('AESkey_Encrypted.enc', 'r')
    response = client.put_file(name+'AESkey.txt.enc', f) #upload AES key for new user, encrypted with their RSA key
    f.close()
    os.remove('AESkey_Encrypted.enc') #remove Encrypted file
    print "user", name, "added"

def removeUser(name): #simply deletes their AES key
    client.file_delete(name+"AESkey.txt.enc")
    print name, "succesfully deleted"

cont = True
while cont == True: #flow of possible commands
    choices = ["upload", "download", "exit", "add user", "delete user"]
    input = ""
    while not input in choices:
        input = raw_input("What would you like to do? ")
    if input == "upload":
        filename = raw_input("Which file would you like to upload? ")
        uploadFile(filename)
        print "succesfully uploaded ", filename
    elif input == "download":
        filename = raw_input("Which file would you like to download? ")
        downloadFile(filename)
        print "succesfully downloaded", filename
    elif input == "add user":
        name = raw_input("User to add? ")
        addUser(name)
    elif input == "delete user":
        name = raw_input("User to delete? ")
        removeUser(name)
    elif input == "exit":
        cont = False
        print "Bye now"
exit()
