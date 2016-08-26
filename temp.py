import pickle

from charm.toolbox.pairinggroup import PairingGroup

group = PairingGroup('SS512')

e = group.random()
print("e")
print(e)

p = pickle.dumps(e)
print("pickle(e)")
print(p)

a = pickle.loads(p)
print("unpickle(pickle(e))")
print(a)
