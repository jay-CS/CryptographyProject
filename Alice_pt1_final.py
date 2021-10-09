import base64
import numpy as np
import random
import rsa
import math

#TODO create function that allows user to enter a message, also allows the user to enter two separate "e" values 
# and then will use the rsa public key generation function to generate a modulus N. Calculates the ciphertexts.
def userInput():
    e1 = int(input("Enter an e value: "))
    e2 = int(input("Enter a second e value: "))
    if math.gcd(e1, e2) != 1:
        raise ValueError("e1 and e2 must be coprime!")
    message = encrypt(input("Enter the message: "))
    pubk,_  = rsa.newkeys(nbits = 2048)
    print("Your modulus is: %d" % pubk.n)
    c1 = (message**e1) % pubk.n
    c2 = (message**e2) % pubk.n
    print(decrypt(attack(c1,c2,e1,e2,pubk.n)).decode("utf-8"))


def modinv(a, m):
    #This portion calculates the extended Euclidian Algorithm (EGCD)
    #We make a list of quotients used to divide the number as it will be used when the algorithm works its way up
    quotients = list()
    b = m
    #This porition obtains the GCD for the two numbers a,b and appends b/a floored (i.e. b//a) to quotients list 
    while a != 0:
        quotients.append(b//a)
        #a becomes b%a, and and b becomes a, these operations occur until a gcd is found (i.e a ==0)
        a, b = b%a, a
    #we set g equal to the gcd, and then set x = 0 and y = 1 as we are going to work our way back up 
    #obtaining the final x,y such that ax + by = 1
    gcd, x, y = b,0,1
    for i in range(len(quotients)-1,-1,-1):
        x,y = y - quotients[i] * x, x
    return x % m, y


#this function takes in the ciphertext, computes the egcd of the exponents to obtain s1 and s2 such that 
#e1*s1 +  e2*s2 = 1, and return the product of C1^e1*s1 + C2^e2*s2
def attack(c1, c2, e1, e2, N):
    if math.gcd(e1, e2) != 1:
        raise ValueError("e1 and e2 must be coprime!")
    s1,s2 = modinv(e1,e2)
    #Equation C1^s1 + C2^s2 = M1^e1*s1 + M2^e2*s2
    return (pow(c1,s1,N) * pow(c2,s2,N)) % N


def encrypt(message):
    m_int = int(base64.b64encode(message.encode("ASCII")).hex(),base = 16)
    return m_int


# The decrypted ciphertext needs to be the resulting message after undergoing the 
# common modulus attack algorithm. Ciphertext must be an int!
def decrypt(ciphertext):
    plaintext = base64.b64decode(bytes.fromhex(hex(ciphertext)[2:]).decode("ASCII"))
    return plaintext

def main():
    print('~~~~~~~~~~ Starting Common Modulus Attack ~~~~~~~~~~')
    #Original values from the problem on the website
    message = attack(239450055536579126410433057119955568243208878037441558052345538060429910227864196906345427754000499641521575512944473380047865623679664401229365345208068050995600248796358129950676950842724758743044543343426938845678892776396315240898265648919893384723100132425351735921836372375270138768751862889295179915967, 138372640918712441635048432796183745163164033759933692015738688043514876808030419408866658926149572619049975479533518038543123781439635367988204599740411304464710538234675409552954543439980522243416932759834006973717964032712098473752496471182275216438174279723470286674311474283278293265668947915374771552561, 3, 65537, 402394248802762560784459411647796431108620322919897426002417858465984510150839043308712123310510922610690378085519407742502585978563438101321191019034005392771936629869360205383247721026151449660543966528254014636648532640397857580791648563954248342700568953634713286153354659774351731627683020456167612375777)
    print('~~~~~~~~~~ Common Modulus Attack Finished! ~~~~~~~~~~')
    print('\nPlaintext message:\n%s' % decrypt(message).decode("utf-8"))

userInput()
main()
