''' Various utility functions. '''

def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n

def align(n, m):
    return (n + m - 1) & bit_not(m - 1)

def str_to_int(str):
    try:
        result = int(str, 0)
        return True,result
    except ValueError:
        return False,0
