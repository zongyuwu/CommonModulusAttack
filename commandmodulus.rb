#!/usr/bin/env ruby

# There is a samll feature in this api
# If you have losts of (c,e) pair you can just put in here then
# the tool will solve all the possible solution for you

require 'openssl'
require 'optparse'

class CommandModulus
  def initialize(n=nil, earr=nil, carr=nil) #Set up argv from new method
    @N, @E, @C, @EP, @CP, @M = nil, [], [], [], [], []
    @N = n
    @E = earr.map { |i| i.to_i } if !earr.nil?
    @C = carr.map { |i| i.to_i } if !carr.nil?
    @EP, @CP = [], []
    @M = []
  end

  def inputcipher(cfarr) #cfarr is array
    cfarr.each do |cf|  
      @C << File.read(cf).unpack("H*")[0].to_i(16)  #Put into and traslate into big int and put into array C
    end
  end

  def input_n_file(n)
    rsa = OpenSSL::PKey::RSA.new File.read(n)
    @N = rsa.params["n"].to_i
  end

  def input_e_file(kfarr) #only support one modulus now
    kfarr.each do |kf| 
      rsa = OpenSSL::PKey::RSA.new File.read(kf)
      @E << rsa.params["e"].to_i
    end
  end

  def exploit
  #http://crypto.stackexchange.com/questions/1614/rsa-cracking-the-same-message-is-sent-to-two-different-people-problem
    sanitycheck
    @EP, @CP = find_ec_pair #EP = e pair ( which two is co-prime) # @CP = c pair
    abp = []
    @EP.each do |ep|
      a, b = extended_gcd(ep[0], ep[1])
      abp << [a, b]
    end
    abp.zip(@CP).each do |v|
      p v
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

  def expcore(v, neg) #see the link in the exp then you will know what is this
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
    else
      raise "Some error in expcore"
    end
    return m
  end

  def invmod(e, et)
    e.to_bn.mod_inverse(et).to_i
  end

  def find_ec_pair
    tmpep = []
    tmpcp = []
    @E.each_with_index do |v1, i1|
      @E.drop(i1).each_with_index do |v2, i2|
        p [i1, i2]
        if v1.gcd(v2) == 1
          tmpep << [v1, v2]
          tmpcp << [@C[i1], @C[i2+i1]]
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

class ARGVPraser
  def initialize
    @@options = {}
    @banner = "Usage commandmodulus.rb [options]"
    OptionsParser.new do |opts|
      opts.banner = @banner

      opts.on("-f F", String, :required, "File to read (C,E)") do |v|
        @@options[:F] = v
      end

      opts.on("-i I", String, :required, "Input (C,N) in integer") do |v|
        @@options[:I] = v
      end
    end.parse!
    exit if sanitycheck == false
    @carr = @@options[:F].nil? ? nil : file
    @parr = @@options[:I].nil? ? nil : input
  end

  def carr
    @carr
  end

  def parr
    @parr
  end

private
  def sanitycheck
  end

  def file
  end

  def input
  end
end
