#A password manager 

import random
import string

length = 15
random_string = ''.join(random.choices(string.ascii_letters +string.digits+ string.punctuation, k=length))
print(random_string)