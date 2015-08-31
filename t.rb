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

def extended_gcd2(a, b)

  # trivial case first: gcd(a, 0) == 1*a + 0*0  
  return 1, 0 if b == 0

  # recurse: a = q*b + r
  q, r = a.divmod b
  s, t = extended_gcd(b, r)

  # compute and return coefficients:
  # gcd(a, b) == gcd(b, r) == s*b + t*r == s*b + t*(a - q*b)
  return t, s - q * t
end


#p extended_gcd(9,13)
p1 = 111829617750571968997433693599496836641054695073863393840106916889789508571207554612392616510159168126852868310694153100708317480279493146524684427535339599
p2 = 11175523999153391637619724547209491349815698538656572443838473636896524059905833901005414536294369978526500224010603676748674624857690274690483791338248729
p extended_gcd2(p1, p2)
