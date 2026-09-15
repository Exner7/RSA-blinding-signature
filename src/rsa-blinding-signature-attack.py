from DigitalSignatures.string2int import string2int


"""
This script demonstrates the RSA Blinding Signature Attack.
It includes key generation, message signing, and signature extraction.

Note:
This script assumes that the string2int function
is defined in the DigitalSignaturesExercise1.string2int module.
"""


# RSA Key Generation (server-side)

p, q = 7, 11  # The two prime numbers, as given in the instructions
N = p * q  # Calculate the product of the two primes `N`

# Calculate the value of Euler's totient function at `N`
t = (p - 1) * (q - 1)

e = 7  # Set public exponent, as given in the instructions

# Calculate the private exponent `d` (private key),
# as the multiplicative inverse of the public exponent mod `t`
d = pow(e, -1, t)


# Server message signing (as API)
def sign(M):
    return pow(M, d, N)


# Get the integer representation
# of the message "flag"
M = string2int("flag")


# To validate results in the demo
# calculate the signature for `M`
# if it was allowed by the server
S = sign(M)
print("Target signature S:", S)


# The RSA Blinding Signature Attack:

# Calculate the alternative message `W`
W = 2**e * M

# Get the signature for `W`
Z = sign(W)

# Extract target signature from `Z`
print("Extracted signature Z:", pow(2, -1, N) * Z % N)
