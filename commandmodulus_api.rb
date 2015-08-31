#!/usr/bin/env ruby
require 'openssl'

class CommandModulus
  def initialize(n=nil, earr=nil, carr=nil)
    @N, @E, @C, @EP, @CP, @M = nil, [], [], [], [], []
    @N = n
    @E = earr.map { |i| i.to_i } if !earr.nil?
    @C = carr.map { |i| i.to_i } if !carr.nil?
    @EP, @CP = [], []
    @M = []
  end

  def inputcipher(cfarr) #cfarr is array
    cfarr.each { |cf|  @C << File.read(cf).unpack("H*")[0].to_i(16) }
    puts "------------"
    p @C
    puts "------------"
  end

  def inputkeyfile(kfarr) #only support one modulus now
    a = OpenSSL::PKey::RSA.new File.read(kfarr[0])
    @N = a.params["n"].to_i
    p @N
    kfarr.each do |kf| 
      rsa = OpenSSL::PKey::RSA.new File.read(kf)
      @E << rsa.params["e"].to_i
    end
  end

  def exploit
  #http://crypto.stackexchange.com/questions/1614/rsa-cracking-the-same-message-is-sent-to-two-different-people-problem
    sanitycheck
    @EP, @CP = find_ec_pair
    abp = []
    @EP.each do |ep|
      a, b = extended_gcd(ep[0], ep[1])
      abp << [a, b]
    end
    abp.zip(@CP).each do |v|
      if v[0][0]  < 0 #a<0
        @M << expcore(v, "a")
      elsif v[0][1] < 0 #b<0
        @M << expcore(v, "b")
      else
        @M << expcore(v, nil) #a and b >0
      end
    end
    return @M
  end

  def inttostring
    m_char = []
    @M.each do |m|
      c_chr = ""
      until m == 0
        c_chr = "#{c_chr}#{(m%(16**2)).chr}"
        m /= (16**2)
      end
      m_char << c_chr.reverse
    end
    return m_char
  end

private

  def expcore(v, neg)
    a, b  = v[0][0], v[0][1]
    c1, c2 = v[1][0], v[1][1]
    case neg
    when nil
      m = ( c1.to_bn.mod_exp(a, @N).to_i * c2.to_bn.mod_exp(b, @N).to_i ) % @N
    when "a"
      i = invmod(c1, @N)
      m = ( c2.to_bn.mod_exp(b, @N).to_i * i.to_bn.mod_exp(-a, @N).to_i ) % @N
    when "b"
      i = invmod(c2, @N)
      m = ( c1.to_bn.mod_exp(a, @N).to_i * i.to_bn.mod_exp(-b, @N).to_i ) % @N
    end
    return m
  end

  def extended_gcd2(a, b)
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
    g, x = extended_gcd2(e, et)
    if g != 1
      raise 'Teh maths are broken!'
    end
    x % et
  end

  def find_ec_pair
    tmpep = []
    tmpcp = []
    @E.each_with_index do |v1, i1|
      @E.drop(i1).each_with_index do |v2, i2|
        if v1.gcd(v2) == 1
          tmpep << [v1, v2]
          tmpcp << [@C[i1], @C[i2]]
        end
      end
    end
    return tmpep, tmpcp
  end

  def extended_gcd(a, b)
    #https://gist.github.com/gpfeiffer/4013925
    # trivial case first: gcd(a, 0) == 1*a + 0*0  
    return 1, 0 if b == 0
    # recurse: a = q*b + r
    q, r = a.divmod b
    s, t = extended_gcd(b, r)
    # compute and return coefficients:
    # gcd(a, b) == gcd(b, r) == s*b + t*r == s*b + t*(a - q*b)
    return t, s - q * t
  end

  def sanitycheck
    raise "Modulus shoud not be nil" if @N.nil?
    raise "Cipher shoud not be nil" if @C.nil?
    raise "Public Exponent shoud not be nil" if @E.nil?
    raise "Should give me at least two C and e pair" if @E.length <= 1 || @E.length <= 1
    raise "Length c and n does not equal" if @E.length != @C.length 
    raise "None of the e pair is coprime" if coprimecheck
  end

  def coprimecheck
    chk = true
    @E.each_with_index do |v1, i|
      @E.drop(i).each do |v2|
        chk = false if v1.gcd(v2) == 1
      end
    end
    return chk
  end
end

#n = 179
#earr = [9, 13]
#carr = [32, 127]
#a = CommandModulus.new(n, earr, carr)
n = 145518833165208701702495434418090057237357773728604886677171619886760738590612864163090559810613912794655742223553389091051900542010866301916626770497281177766506929055320989583436574608961244872048578931949979358219350651028045767048645090953540198249601929929401892591733388302476848668386649536163336622913
earr = [3,7]
carr = [ 489115219897472501492987888013066422961526185059801353150323856814508992495086602484634378216, 15727199419504036641713398229364050308305557239408963626842287357880582438802179229304032481287163717647634391139287700180665935794615717468229760021779707705425534816073418529966489268411105552241835951206390825509894845964982431261179397876949615188107074009866707983196951971693042725924985324102724178436072 ]


cparr = ["./cipher.txt", "./cipher1.txt", "./cipher2.txt", "./cipher3.txt"]
pubkarr = ["./pub.pem", "./pub1.pem", "./pub2.pem", "./pub3.pem"]
a = CommandModulus.new(n, earr, carr)
#a.inputcipher(cparr)
#a.inputkeyfile(pubkarr)
a.exploit
p a.inttostring
