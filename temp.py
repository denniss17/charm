import pickle

from charm.toolbox.pairinggroup import PairingGroup

group = PairingGroup('SS512')

print("pickle(group)")
print(pickle.dumps(group))

print("unpickle(pickle(group))")
print(pickle.loads(pickle.dumps(group)))

e = group.random()
print("e")
print(e)

p = pickle.dumps(e)
print("pickle(e)")
print(p)

a = pickle.loads(p)
print("unpickle(pickle(e))")
print(a)
