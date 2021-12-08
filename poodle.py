
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC
from Crypto import Random
import time

# source : https://www.openssl.org/~bodo/ssl-poodle.pdf
# source : https://www.acunetix.com/blog/web-security-zone/what-is-poodle-attack/

def log(message, type="none", bold=False, underlined=False):
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    ORANGE = '\033[93m'
    UNDERLINE = '\033[4m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

    prefix = ""
    if(underlined):
        prefix += UNDERLINE
    if(bold):
        prefix += BOLD

    if(type == "warning"):
        print(prefix+ORANGE+message+ENDC)
    elif(type == "info"):
        print(prefix+BLUE+message+ENDC)
    elif(type == "success"):
        print(prefix+GREEN+message+ENDC)
    else:
        print(prefix+message+ENDC)

# This class represents a web server which uses SSL v3 protocol
class Server:

    # The server is initialisated with the cipher key and the authentication key
    def __init__(self, cipherKey, authenticationKey):
        self.cipherKey = cipherKey
        self.authenticationKey = authenticationKey

    # This method handles the request received from clients
    # Returns True if request is valid, else False
    def handleRequest(self, request):
        if(self.decrypt(request) == False):
            return False
        else: 
            return True

    # This method decrypts an encrypted request
    # Returns False if an error occurs, else the plain text
    def decrypt(self, encryptedRequest):
        IV = encryptedRequest[0:AES.block_size] # Initialisation vector
        encryptedData = encryptedRequest[AES.block_size:] # Encrypted data

        cipher = AES.new(self.cipherKey, AES.MODE_CBC, IV) 
        decryptedData = cipher.decrypt(encryptedData) # Decrypted data
        
        paddingSize = decryptedData[-1] # The padding size corresponds to the last byte of the last block

        decryptedDataWithoutPadding = decryptedData[:-paddingSize] # We remove the padding
        oldMac = decryptedDataWithoutPadding[-AES.block_size:] # We get the message's MAC
        decryptedText = decryptedDataWithoutPadding[:-AES.block_size] # We remove the message's MAC

        hmac = HMAC.new(self.authenticationKey) # We recalculate the mac to check the integrity
        hmac.update(decryptedText)
        newMac = hmac.digest()

        # If the text has not been modified
        if(newMac == oldMac):
            return decryptedText
        else:
            return False 



# This class represents an attacker who get client requests before redirecting them to the server (Man in the middle attack)
class Attacker:

    # The attacker is initialized with a client and a server
    def __init__(self, client, server):
        self.client = client
        self.server = server

    # This method gets a client request before redirecting is to the server
    def handleRequest(self, request):
        self.lastRequest = request
        self.lastRequestAccepted = self.server.handleRequest(request)

    # This method launches the poodle attack
    # It takes in arguments : 
    #   - blockToDecrypt : the number of the block to start decrypting (it starts by the last byte of the block) (starts at 0)
    #   - lengthToDecrypt : the number of caracters to decrypt (from the last byte of the blockToDecrypt block)
    def attack(self, blockToDecryptNumber, lengthToDecrypt):
        log("===========================", "none", True)
        log("    START OF THE ATTACK", "none", True)
        log("   blockToDecryptNumber = "+str(blockToDecryptNumber), "info")
        log("   lengthToDecrypt = "+str(lengthToDecrypt), "info")
        log("===========================", "none", True)
        decryptedFullRequest = "" # Stores decrypted caracters

        path = "/" # Path of the request (false path)
        body = "A"*lengthToDecrypt # Body of the request

        log("---===---===---===---===---", "none", True)
        log("  Rajout d'octets au body pour obtenir un bloc complet", "warning", True)
        # Find the correct body size to have last block full of padding
        # We know that the last block if full of padding when a new block is added (means that the length of padding has been put in the new block and is therefore intialized to AES.block_size (block size = AES.block_size))
        self.client.sendRequest(path, body)
        lastRequestSizeInBlock = len(self.lastRequest)//AES.block_size # 
        increaseBodySize = True
        while(increaseBodySize):
            time.sleep(0.1)
            body = body + "A"
            self.client.sendRequest(path, body) # The requests is going to be handled in "Attacker.handleRequest" method
            newRequestSizeInBlock = len(self.lastRequest)//AES.block_size
            log("    Body actuel : " + body)
            log("     Nombre de blocs : " + str(newRequestSizeInBlock)+"\n", "", True)
            if(lastRequestSizeInBlock != newRequestSizeInBlock): # If the size has changed, it means that a new block has been added
                increaseBodySize = False
            lastRequestSizeInBlock = newRequestSizeInBlock
        
        log("  Padding terminé", "success", True)
        time.sleep(2)

        # This loop is used to decrypt each asked caracter
        for i in range(lengthToDecrypt):
            time.sleep(0.25)
            nbOfRequests = 0
            requestRejectedByServer = True # Registers if the server has validated the request or not
            while(requestRejectedByServer): # While the server rejects the request (because the MAC is not valid)
                nbOfRequests += 1
                self.client.sendRequest(path, body) # We make the client sending a new request (often thanks to a malicious JS script)
                blockToDecrypt = self.lastRequest[(blockToDecryptNumber*AES.block_size):((blockToDecryptNumber+1)*AES.block_size)] # block to decrypt
                newEncryptedRequest = self.lastRequest[:-AES.block_size] + blockToDecrypt # We remove the padding to replace it by the block to decrypt thanks to the fact that the padding is not included in the MAC
                if(self.server.handleRequest(newEncryptedRequest)): # If the server accepts the new request
                    log("---===---===---===---===---", "none", True)
                    log("  Decryption succeeded in "+str(nbOfRequests)+" requests", "success", True)
                    requestRejectedByServer = False
                    blockBeforeToDecryptLastByte = newEncryptedRequest[blockToDecryptNumber*AES.block_size-1] # Last byte of the block just before the block to decrypt
                    blockBeforeLastBlockLastByte = newEncryptedRequest[-AES.block_size-1] # Last byte of the before last block
                    decryptedLastByteOfBlockToDecrypt = blockBeforeLastBlockLastByte^AES.block_size^blockBeforeToDecryptLastByte # P(i) = C(i-1) ^ x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,AES.block_size ^ C(n-1)
                    decryptedLastCharOfBlockToDecrypt = chr(decryptedLastByteOfBlockToDecrypt) # Decrypted char
                    decryptedFullRequest += decryptedLastCharOfBlockToDecrypt # Add decrypted char to decrypted request

                    log("  Path : "+path)
                    log("  Body : "+body)
                    log("  Character decrypted : '"+decryptedLastCharOfBlockToDecrypt+"'", "none", True)

                    body = body[:len(body)-1] # Decrease body length
                    path = path + "A" # Increase path length -> the two operations are made to shift the wanted informations to the right, in order to have the next wanted byte at the end of the blockToDecryptNumber block

        decryptedFullRequest = decryptedFullRequest[::-1] # We reverse the request because it has been decrypted in reverse
        log("===========================", "none", True)
        log("     END OF THE ATTACK", "none", True)
        log("   decryptedFullRequest = \""+decryptedFullRequest+"\"", "success", True)
        log("===========================", "none", True)
        return True

# This class represents a client which connects to a server
class Client:
    
    # The client is initialised with the cipherKey, the authenticationKey and the server
    def __init__(self, cipherKey, authenticationKey, server):
        self.cipherKey = cipherKey
        self.authenticationKey = authenticationKey
        self.server = server

    # This method encrypts the plainText with the cipher key and calculated the mac thanks to the authentication key
    def encrypt(self, plainText):
        IV = Random.new().read(AES.block_size) # Random initialization vector

        hmac = HMAC.new(self.authenticationKey) # Mac calculation initialization
        hmac.update(bytes(plainText, 'ascii'))
        mac = hmac.digest() # Calculation of the mac of the text

        toEncrypt =  bytes(plainText, 'ascii') + mac # Request to encrypt = plain text + mac of plain text

        # We add the padding in order to have the request size as a multiple of AES.block_size
        paddingSize = AES.block_size-(len(toEncrypt)%AES.block_size)
        if(paddingSize > 1):
            toEncrypt += Random.new().read(paddingSize-1)
        toEncrypt += bytes([paddingSize-1]) # Request to encrypt = plain text + mac of plain text + padding (=multiple of AES.block_size)


        cipher = AES.new(self.cipherKey, AES.MODE_CBC, IV)
        encryptedText = cipher.encrypt(toEncrypt) # Encrypted text = encryption(plain text + mac of plain text + padding)
        
        encryptedRequest = IV + encryptedText # Encrypted request = IV + encryption(plain text + mac of plain text + padding) 

        return encryptedRequest

    # This method formumlates and sends the request to the server
    def sendRequest(self, path, data):
        data = "POST: "+path+" Cookie: "+self.getCookie()+" "+data # The request is formed in : "POST: "+path+cookie+data
        
        request = self.encrypt(data) # We encrypt the data

        self.server.handleRequest(request) # We send it to the server

    # Private cookie of the client
    def getCookie(self):
        return "sessionuuid=[WjM9~t@v^YdHPJ.As?]"

# We consider that the handshake to determine common keys has already been made, we are not interested by this part
CIPHER_KEY = get_random_bytes(AES.block_size)
AUTHENTICATION_KEY = get_random_bytes(AES.block_size)

server = Server(CIPHER_KEY, AUTHENTICATION_KEY) # Basic web server
client = Client(CIPHER_KEY, AUTHENTICATION_KEY, server) # Basic client
client.sendRequest("/index.html", "") # Basic request from the client


# We consider that at this moment, the hacker starts his attack
# The "forced" downgrade to SSLv3 has been made too and that the attacker has realized a man in the middle attack in order to intercept client requests and that he has put a malicious JS script on the client page in order to make him send request as the attacker wants
attacker = Attacker(client, server)
client.server = attacker # The client's server becomes the attacker, but the client still thinks that he is still communicating with the server because the attacker is still forwarding client's request to the server

attacker.attack(3, 32) # In our example, we know that the cookies's informations are stored in the 3rd and 4th block (so it is 32 caracters long and finish at the end of the 4th block (number 3 because blocks start at 0))