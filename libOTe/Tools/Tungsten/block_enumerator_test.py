
# https://stackoverflow.com/questions/58069431/find-all-binary-strings-of-certain-weight-has-fast-as-possible
# n is total length
# h is the desired output weight
def binary_array_all_combinations(n, k):
    limit=1<<n
    val=(1<<k)-1
    while val < limit:
        yield "{0:0{1}b}".format(val,n)
        minbit=val&-val # rightmost 1 bit
        fillbit = (val+minbit)&~val  # rightmost 0 to the left of that bit
        val = val+minbit | (fillbit//(minbit<<1))-1

n = 3
w = 2

# find all G
# find all Gi (all bitstrings of length n/sigma * sigma^2)
# (remaining elements not on the diagonal are 0)

# find all inputs x of weight w
for x in binary_array_all_combinations(n,w):
    xi = [int(b) for b in x]
    print(xi)