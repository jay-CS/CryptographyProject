import base64
import numpy as np
import random
import rsa
import math




def modinv(a, m):
    #This portion calculates the extended Euclidian Algorithm (EGCD)
    #We make a list of quotients used to divide the number as it will be used when the algorithm works its way up
    quotients = list()
    b = m
    #This porition obtains the GCD for the two numbers a,b and appends b/a floored (i.e. b//a) to quotients list 
    while a != 0:
        quotients.append(b//a)
        a, b = b%a, a
    
    g, x, y = b,0,1
    for i in range(len(quotients)-1,-1,-1):
        x,y = y - quotients[i] * x, x
    #print(g,x,y)
    if g != 1:
        raise ValueError('Modular inverse does not exist.')
    else:
        return x % m


def attack(c1, c2, e1, e2, N):
    if math.gcd(e1, e2) != 1:
        raise ValueError("Exponents e1 and e2 must be coprime")
    s1 = modinv(e1,e2)
    s2 = (1 - e1 * s1) / e2
    
    #Equation C1^x + C2^y = M1^e1*x + M2^e2y
    m1 = pow(c1,s1,N)
    m2 = pow(c2,int(s2),N)
    return (m1 * m2) % N


def encrypt(message):
    m_int = int(base64.b64encode(message.encode("ASCII")).hex(),base = 16)
    return m_int


# The decrypted ciphertext needs to be the resulting message after undergoing the 
# common modulus attack algorithm. Ciphertext must be an int!
def decrypt(ciphertext):
    plaintext = base64.b64decode(bytes.fromhex(hex(ciphertext)[2:]).decode("ASCII"))
    return plaintext

def main():
    print('[+] Started attack...')
    message = attack(239450055536579126410433057119955568243208878037441558052345538060429910227864196906345427754000499641521575512944473380047865623679664401229365345208068050995600248796358129950676950842724758743044543343426938845678892776396315240898265648919893384723100132425351735921836372375270138768751862889295179915967, 138372640918712441635048432796183745163164033759933692015738688043514876808030419408866658926149572619049975479533518038543123781439635367988204599740411304464710538234675409552954543439980522243416932759834006973717964032712098473752496471182275216438174279723470286674311474283278293265668947915374771552561, 3, 65537, 402394248802762560784459411647796431108620322919897426002417858465984510150839043308712123310510922610690378085519407742502585978563438101321191019034005392771936629869360205383247721026151449660543966528254014636648532640397857580791648563954248342700568953634713286153354659774351731627683020456167612375777)
    print('[+] Attack finished!')
    # message = attack(98165528588897581357762737834689451362252757422664514540538121132831138195216264938258509140640778717781569080958991098729015566777580593509402612574625430419832053337731308491289074351255823858676879185727045495590514663530030231806055096448879914474800546120932100906434044055982738517132870631903309747388,102475188247563848286945915380476667802602854876368431885335322709108972931825158123667293750369168229919151668978059761534237040449685498674713242003659107451198242719915205456598334223051250662805244834468165714315564160456345356775214718947496000390960566077219957635569079685758176360540536491609062295912,15,13,103109065902334620226101162008793963504256027939117020091876799039690801944735604259018655534860183205031069083254290258577291605287053538752280231959857465853228851714786887294961873006234153079187216285516823832102424110934062954272346111907571393964363630079343598511602013316604641904852018969178919051627)
    print('\nPlaintext message:\n%s' % decrypt(message).decode("utf-8"))

main()

#TODO try using larger numbers like 2048 bit and see if it works

