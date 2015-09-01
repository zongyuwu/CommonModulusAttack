#!/usr/bin/env ruby

require 'openssl'
require 'base64'

Testfile_Dir = "./test/" #where the genenerated file in
Plaintext = ["plaintext.txt", "plaintext1.txt"]
Ciphertext = [ "cipher.txt", "cipher1.txt", "cipher2.txt", "cipher3.txt" ]
PublicKey = [ "pub.pem", "pub1.pem", "pub2.pem", "pub3.pem" ]

Plaintext.map! { |e| e = "#{Testfile_Dir}#{e}" }
Ciphertext.map! { |e| e = "#{Testfile_Dir}#{e}" }
PublicKey.map! { |e| e = "#{Testfile_Dir}#{e}" }

Earr = [3, 7, 3, 65537] #Set up the public exponent

class Gen
  def initialize(e, bit)
    ra = OpenSSL::PKey::RSA.new(bit)
    rb = OpenSSL::PKey::RSA.new(bit)
    @rsa = [ra, ra, rb, rb]
    @E = e
    @N, @C = [], [], [], []
    @M = readtext(Plaintext)
    @rsa.each { |r| @N << r.params["n"].to_i }
    @C, @Ci = enc
  end
  
  def display_params
    print "N="
    p @N
    puts "----------"
    print "e="
    p @E
    puts "----------"
    print "C="
    p @Ci
  end
 
  def writecip
    Ciphertext.zip(@C).each do |cf, c|
      File.open(cf, "w") { |f| f.write(c) }
    end
  end

  def writepub
    @rsa.zip(PublicKey, @E).each do |rsa, pk, e|
      r = RSAtool.new(rsa.params["p"].to_i, rsa.params["q"].to_i, e.to_i )
      File.open(pk, "w") { |f| f.write(r.to_pem) }
    end
  end 

private

  def enc 
    ## to do : judge the plain text length and N
    carr = []
    carr_int = []
    @M.zip(@E, @N).each do |m, e, n|
      c_chr = ""
      c = m.to_bn.mod_exp(e, n).to_i
      c_int = c
      until c == 0
        c_chr = "#{c_chr}#{(c%(16**2)).chr}"
        c /= (16**2)
      end
      carr_int << c_int
      carr << c_chr.reverse
    end
    return carr, carr_int
  end


  def readtext(file)
    tmp = []
    file.each do |f|
      2.times do 
        tmp << File.read(f).unpack("H*")[0].to_i(16)
      end
    end
    return tmp
  end
end

class RSAtool
  def initialize(p,q,e=65537)
    p,q = q,p if q>p
    @v = 0
    @p = p
    @q = q
    @n = @p*@q
    @e = e
    @d = invmod(@e, ((@p-1)*(@q-1)))
    @exp1 = @d % (@p-1)
    @exp2 = @d % (@q-1)
    @coef = invmod(@q, @p)
    version = OpenSSL::ASN1::Integer.new(@v)
    modulus = OpenSSL::ASN1::Integer.new(@n)
    publicExponent = OpenSSL::ASN1::Integer.new(@e)
    privateExponent = OpenSSL::ASN1::Integer.new(@d)
    prime1 = OpenSSL::ASN1::Integer.new(@p)
    prime2 = OpenSSL::ASN1::Integer.new(@q)
    exponent1 = OpenSSL::ASN1::Integer.new( @d % (@p-1))
    exponent2 = OpenSSL::ASN1::Integer.new( @d % (@q-1))
    coefficient = OpenSSL::ASN1::Integer.new( invmod(@q, @p) )
    @seq = OpenSSL::ASN1::Sequence.new( [version, modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient] )
  end

  def to_der
    @seq.to_der
  end

  def to_pem
    header = "-----BEGIN RSA PRIVATE KEY-----\n" 
    tail = "-----END RSA PRIVATE KEY-----\n"
    return "#{header}#{Base64.encode64(@seq.to_der)}#{tail}"
  end

  def extended_gcd(a, b)
    last_remainder, remainder = a.abs, b.abs
    x, last_x, y, last_y = 0, 1, 1, 0
    while remainder != 0
      last_remainder, (quotient, remainder) = remainder, last_remainder.divmod(remainder)
      x, last_x = last_x - quotient*x, x
      y, last_y = last_y - quotient*y, y
    end
    return last_remainder, last_x * (a < 0 ? -1 : 1)
  end

  def invmod(e, et)
    g, x = extended_gcd(e, et)
    if g != 1
      raise 'Teh maths are broken!'
    end
    x % et
  end
end

g = Gen.new(Earr, 1024)
g.writepub
g.writecip
g.display_params
