import pickle
import unittest

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT


class PairingTest(unittest.TestCase):
    def testElementPickle(self):
        group = PairingGroup('SS512')
        elements = {
            'ZR': group.random(ZR),
            'G1': group.random(G1),
            'G2': group.random(G2),
            'GT': group.random(GT)
        }

        pickled_elements = {name: pickle.dumps(element) for name, element in elements.items()}
        unpickled_elements = {name: pickle.loads(pickled) for name, pickled in pickled_elements.items()}

        for name, unpickled in unpickled_elements:
            self.assertEqual(unpickled_elements, elements[name],
                             'Element in group %s should be the same after pickle and unpickle' % name)


if __name__ == "__main__":
    unittest.main()
