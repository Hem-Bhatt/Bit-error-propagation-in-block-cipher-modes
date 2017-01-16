# Aes-Modes-Using-Pycrypto
Python version used: 2.7.9
External Library used: Pycrypto


The program needs to be in the same directory as that of the test files. The code takes as input a file (works for every kind of file, including videos & images) within the same folder as the python file and outputs the encrypted and the decrypted file for every mode and measures the time taken for this process for every mode. The Encrypted file has the file structure "Modename_Encrypted_originalfilename". The decrypted file has the structure "Modename_Decrypted_originalfilename".

Bit error propogation is checked by 1st encrypting the file, changing the bits inside the  encrypted file and decrypting the file for the same mode. The files were tested with all the 3 possible AES key sizes ( 128,192,256 bits ) and on 4 files of different formats with different sizes (15.74 MB,85.833 MB, 163.656 MB, 390.182 MB)

Graphs:-

The graph for CFB mode is drawn seperately below in both the excel files as it takes significantly more time than the rest of the modes.
