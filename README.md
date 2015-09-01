# CommanModulusAttack
In RSA, when using same Modulus N and different public Exponent e in rsa and the plaintext M are the same which does not padding. If we have at least such (C1, E1, N) and (C2, E2, N) pairs. The tool can efficiently find plaintext M without any private information.

**How to use**  
  * api  
    Input argument by calling new
```ruby
# == Simple test case == #
n = 179
earr = [9, 13]
carr = [32, 127]
a = CommandModulus.new(n, earr, carr) #set up 
p a,exploit #do the exploit and print as int
p a.inttostring #print the exploit result into string
# ====================== #
``` 
 
    Input argument by file  

```ruby
testfile_dir = "./test/"
cparr = ["cipher.txt", "cipher1.txt", "cipher2.txt", "cipher3.txt"]
pubkarr = ["pub.pem", "pub1.pem", "pub2.pem", "pub3.pem"]
cparr.map! { |e| e = "#{testfile_dir}#{e}" }
pubkarr.map! { |e| e = "#{testfile_dir}#{e}" }
a = CommandModulus.new
a.inputcipher(cparr) #all the cipher you have
a.input_e_file(pubkarr) #all the public exponent you have  
#**NOTICE**" : the ciphert and public expnent should in pair
# eg. cparr = (C1, C2, C3)
#     eparr = (E1, E2, E3)
a.input_n_file("#{testfile_dir}/pub2.pem") #input the public modulus 
#If you dont which n to use you can try for each n
#For now, we  does not support for multiple N
p a.exploit # do the exploit and print as int
p a.inttostring #print the exploit result into string
```  
  * tool

