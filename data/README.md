# Data

There is no external dataset. RSA keypairs are generated on the fly by
`cryptosentry.rsa.generate_keypair`, using primes produced by
`cryptosentry.primes.generate_prime` (Miller-Rabin primality testing over
Python's arbitrary-precision integers). See the main README's Method
section for what's real (actual random bignum primes, actual modular
exponentiation) versus what's a cited theoretical estimate (the classical
vs. quantum complexity comparison, which is not a simulation of either
algorithm).
