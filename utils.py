''' Various utility functions. '''

def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n

def align(n, m):
    return (n + m - 1) & bit_not(m - 1)
