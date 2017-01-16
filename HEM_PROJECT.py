#Implement DES/AES Encryption and Decryption with ECB, CBC, CFB, OFB, CTR
###################### BY HEM BHATT #####################################
#Reference https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html
#Reference https://recalll.co/app/?q=python%20-%20Pycrypto%3A%20Incrementing%20CTR%20Mode%20-%20Stack%20Overflow
#Reference http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/
#Seperate Encrypt and decrypt functions DONE, CHecking Bit error propagation-DOne!!!

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import DES           #Incase we want to use DES
from timeit import default_timer as timer         #To measure Encryption/Decryption Timings
from Crypto.Util import Counter     #Needed to increment counter in CTR mode
import struct,random
import sys
import os


class modes(object):

    def __init__(self):
        self.key=chosenkey
           
    def ECB(self):             
        
        memory_usage=64*1024                        #Used for faster execution
        f_encrypted = 'ECB_Encrypted_'+filen         #Filename Structure for encrypted files
        f_encrypted_2= 'ECB_Decrypted_'+filen         #Filename Structure for decrypted files
        encrypt_value = AES.new(chosenkey, AES.MODE_ECB) #Does not require any Initialization vector or randomness
        filesize = os.path.getsize(filen)
        s=timer()
      
        with open(filen, 'rb') as encrypt_file:        #Opens the inputfilename 
              
              
              
              with open(f_encrypted, 'wb') as f_e:      #Creates the encrypted file and opens it with read and write permissions.
                                          
                  f_e.write(struct.pack('<Q', filesize))    #Ensures that the encrypted file is of the same size as that of the original file
                  

                  while True:
                      
                      
                      mem_use = encrypt_file.read(memory_usage)     #Encrypts every memory block with our variable memory usage parameter
                      if len(mem_use) == 0:
                              break
                      elif len(mem_use) % 16 != 0:
                          mem_use += ' ' * (16 - len(mem_use) % 16)     #Adds padding incase the memory_usage is not divisible by 16

                      f_e.write(encrypt_value.encrypt(mem_use))  #Encryption ends here
        ee=timer()
        print("\nAES-ECB Encryption time:")
        print(ee-s)
        c=raw_input("\nIs the file that you want to decrypt same as the file? type y/n:")
        if c=="n":
            f_encrypted=raw_input("\nEnter the file which you want to decrypt:") # The file has to be Encrypted using ECB mode only for proper decryption!
        elif c=="y":
            f_encrypted=f_encrypted
        else:
            print("Please enter a valid response:")
            sys.exit()
        sd=timer()
        
        
        with open(f_encrypted, 'rb') as encrypt_file:                        #Starts reading the input to the decryption 
            o_size = struct.unpack('<Q', encrypt_file.read(struct.calcsize('Q')))[0]
            
            decryptor_value = AES.new(chosenkey, AES.MODE_ECB) #Uses this value to decrypt the ciphertext chunk by chunk                                          
            with open(f_encrypted_2, 'wb') as f_e:                                                                                               
                while True:                                                                                    
                    mem_use = encrypt_file.read(memory_usage)   
                    if len(mem_use) == 0:
                        break                      
                    f_e.write(decryptor_value.decrypt(mem_use))  #Decrypts ciphertext chunk by chunk
               

        e=timer()
        print("AES-ECB Decryption time:")
        print(e-sd)
       

    def CBC(self):
        memory_usage=64*1024      
        f_encrypted = 'CBC_Encrypted_'+filen
        f_encrypted_2= 'CBC_Decrypted_'+filen
        iv = Random.new().read(AES.block_size)      #Initialization vector must be of the same size as the blocksize since it is XOR'ED
        encrypt_value = AES.new(chosenkey, AES.MODE_CBC,iv)
        filesize = os.path.getsize(filen)
        s=timer()
      
        with open(filen, 'rb') as encrypt_file:
              
              
              
              with open(f_encrypted, 'wb') as f_e:
                                          
                  f_e.write(struct.pack('<Q', filesize))
                  f_e.write(iv)

                  while True:
                      
                      
                      mem_use = encrypt_file.read(memory_usage)
                      if len(mem_use) == 0:
                              break
                      elif len(mem_use) % 16 != 0:
                          mem_use += ' ' * (16 - len(mem_use) % 16)

                      f_e.write(encrypt_value.encrypt(mem_use))  #Encryption ends here

        

        ee=timer()
        print("\nAES-CBC Encryption time:")
        print(ee-s)
        c=raw_input("\nIs the file that you want to decrypt same as the file? type y/n:")
        if c=="n":
            f_encrypted=raw_input("\nEnter the file which you want to decrypt:")
        elif c=="y":
            f_encrypted=f_encrypted
        else:
            print("Please enter a valid response:")
            sys.exit()
        sd=timer()    
        with open(f_encrypted, 'rb') as encrypt_file:                        
            o_size = struct.unpack('<Q', encrypt_file.read(struct.calcsize('Q')))[0]
            iv = encrypt_file.read(16)
            decryptor_value = AES.new(chosenkey, AES.MODE_CBC, iv)                                          
            with open(f_encrypted_2, 'wb') as f_e:                                                                                                     
                while True:                                                                                    
                    mem_use = encrypt_file.read(memory_usage)
                    if len(mem_use) == 0:
                        break                      
                    f_e.write(decryptor_value.decrypt(mem_use))  #Encryption ends here
                


        e=timer()
        print("AES-CBC Decryption time:")
        print(e-sd)
       

    def CFB(self):
        memory_usage=64*1024      
        f_encrypted = 'CFB_Encrypted_'+filen
        f_encrypted_2= 'CFB_Decrypted_'+filen
        iv = Random.new().read(AES.block_size)      #The initialization vector or Randomness, same size as the AES.blocksize 
        encrypt_value = AES.new(chosenkey, AES.MODE_CFB,iv)
        filesize = os.path.getsize(filen)
        s=timer()
      
        with open(filen, 'rb') as encrypt_file:
              
              
              
              with open(f_encrypted, 'wb') as f_e:
                                          
                  f_e.write(struct.pack('<Q', filesize))
                  f_e.write(iv)

                  while True:
                      
                      
                      mem_use = encrypt_file.read(memory_usage)
                      if len(mem_use) == 0:
                              break
                      elif len(mem_use) % 16 != 0:
                          mem_use += ' ' * (16 - len(mem_use) % 16)

                      f_e.write(encrypt_value.encrypt(mem_use))  #Encryption ends here

        

        ee=timer()
        print("\nAES-CFB Encryption time:")
        print(ee-s)
        c=raw_input("\nIs the file that you want to decrypt same as the file? type y/n:")
        if c=="n":
            f_encrypted=raw_input("\nEnter the file which you want to decrypt:")
        elif c=="y":
            f_encrypted=f_encrypted
        else:
            print("Please enter a valid response:")
            sys.exit()
        sd=timer() 
        with open(f_encrypted, 'rb') as encrypt_file:                        
            o_size = struct.unpack('<Q', encrypt_file.read(struct.calcsize('Q')))[0]
            iv = encrypt_file.read(16)
            decryptor_value = AES.new(chosenkey, AES.MODE_CFB, iv)                                          
            with open(f_encrypted_2, 'wb') as f_e:                                                                                                        
                while True:                                                                                    
                    mem_use = encrypt_file.read(memory_usage)
                    if len(mem_use) == 0:
                        break                      
                    f_e.write(decryptor_value.decrypt(mem_use))  #Encryption ends here
               


        e=timer()
        print("AES-CFB Decryption time:")
        print(e-sd)
        

        
    def OFB(self):
        memory_usage=64*1024      
        f_encrypted = 'OFB_Encrypted_'+filen
        f_encrypted_2= 'OFB_Decrypted_'+filen
        iv = Random.new().read(AES.block_size)      #Blocksize        
        encrypt_value = AES.new(chosenkey, AES.MODE_OFB,iv)
        filesize = os.path.getsize(filen)
        s=timer()
      
        with open(filen, 'rb') as encrypt_file:
              
              
              
              with open(f_encrypted, 'wb') as f_e:
                                          
                  f_e.write(struct.pack('<Q', filesize))
                  f_e.write(iv)

                  while True:
                      
                      
                      mem_use = encrypt_file.read(memory_usage)
                      if len(mem_use) == 0:
                              break
                      elif len(mem_use) % 16 != 0:
                          mem_use += ' ' * (16 - len(mem_use) % 16)

                      f_e.write(encrypt_value.encrypt(mem_use))  #Encryption ends here

        

        ee=timer()
        print("\nAES-OFB Encryption time:")
        print(ee-s)
        c=raw_input("\nIs the file that you want to decrypt same as the file? type y/n:")
        if c=="n":
            f_encrypted=raw_input("\nEnter the file which you want to decrypt:")
        elif c=="y":
            f_encrypted=f_encrypted
        else:
            print("Please enter a valid response:")
            sys.exit()
        sd=timer() 
        with open(f_encrypted, 'rb') as encrypt_file:                        
            o_size = struct.unpack('<Q', encrypt_file.read(struct.calcsize('Q')))[0]
            iv = encrypt_file.read(16)
            decryptor_value = AES.new(chosenkey, AES.MODE_OFB, iv)                                          
            with open(f_encrypted_2, 'wb') as f_e:                                                                                                         
                while True:                                                                                    
                    mem_use = encrypt_file.read(memory_usage)
                    if len(mem_use) == 0:
                        break                      
                    f_e.write(decryptor_value.decrypt(mem_use))  #Encryption ends here
                


        e=timer()
        print("AES-OFB Decryption time:")
        print(e-sd)
        

    def CTR(self):           #Does not require padding   
        
        
        ctr = Counter.new(128) #Creates an instance of Counter class from PyCrypto to increase the counter for every block
        memory_usage=64*1024 
        f_encrypted='CTR_Encrypted_'+filen 
        f_encrypted_2= 'CTR_Decrypted_'+filen    
        encrypt_value = AES.new(chosenkey, AES.MODE_CTR, counter=ctr) #Does not require any Initialization vector or randomnes
        filesize = os.path.getsize(filen)
        s=timer()
        with open(filen, 'rb') as encrypt_file:
              
              
              
              with open(f_encrypted, 'wb') as f_e:
                                          
                  f_e.write(struct.pack('<Q', filesize))
                  

                  while True:
                      
                      
                      mem_use = encrypt_file.read(memory_usage)
                      if len(mem_use) == 0:
                              break
                      

                      f_e.write(encrypt_value.encrypt(mem_use))  #Encryption ends here

        ee=timer()
        print("\nAES-CTR Encryption time:")
        print(ee-s)
        c=raw_input("\nIs the file that you want to decrypt same as the file? type y/n:")
        if c=="n":
            f_encrypted=raw_input("\nEnter the file which you want to decrypt:")
        elif c=="y":
            f_encrypted=f_encrypted
        else:
            print("Please enter a valid response:")
            sys.exit()
        sd=timer() 
        ctr=Counter.new(128)             #Resets the Counter for decrypting it, Without this Decryption is messy.
        with open(f_encrypted, 'rb') as encrypt_file:                        
            o_size = struct.unpack('<Q', encrypt_file.read(struct.calcsize('Q')))[0]
            
            decryptor_value = AES.new(chosenkey, AES.MODE_CTR,counter=ctr)                                          
            with open(f_encrypted_2, 'wb') as f_e:                                                                                               
                while True:                                                                                    
                    mem_use = encrypt_file.read(memory_usage)
                    if len(mem_use) == 0:
                        break                      
                    f_e.write(decryptor_value.decrypt(mem_use))  
                
        e=timer()
        print("AES-CTR Decryption time:")
        print(e-sd)
        

            
        



                             
AES.block_size=16 # AES blocksize in bytes
keysize=int(input("Enter the keysize in bits:"))/8
filen=raw_input("\nEnter the filename:")
chosenkey=os.urandom(keysize) #Generates cryptographically secure pseudo-random numbers 
print("\nOur Key Generated by PseudoRandom Generator is %s:")%chosenkey
modes().ECB()                 #Methods are called from this point
modes().CBC()
modes().CFB()
modes().OFB()
modes().CTR()
    
 

