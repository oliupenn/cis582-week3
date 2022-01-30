import random

from params import p
from params import g

def keygen():
    q=(p-1)/2
    a = random.randrange(1,q,1)
    sk = a
    pk = pow(g,a,p)
    return pk,sk

def encrypt(pk,m):
    r = random.randrange(1,q,1)
    c1 = pow(g,r,p)
    c2 = pow((pow(pk,r,p)*pow(m,1,p)),1,p)
    return [c1,c2]

def decrypt(sk,c):
    m = pow((pow(c[1],1,p)*pow(c[0],-sk,p)),1,p)
    return m
