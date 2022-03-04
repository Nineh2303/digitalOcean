import random
import string


def getRandomCartId() :
    letters = string.ascii_uppercase + string.digits
    result = ''.join(random.choice(letters) for i in range(10))
    return result
def getRandomItemId(cartId) : 
    letters = string.ascii_uppercase + string.digits
    result = ''.join(random.choice(letters) for i in range(3))
    return str(cartId) + '_'+ result
