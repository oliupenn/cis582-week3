import math

def num_BTC(b):
    quotient = int(b / 210000)
    remainder = b % 210000
    c = 0
    reward = 50
    for i in range(quotient):
        c += 210000 * reward
        reward *= 0.5
    c += remainder * reward
    return c
