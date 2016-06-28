from charm.toolbox.usertree import BinaryUserTree
import unittest


class UserTreeTest(unittest.TestCase):
    def setUp(self):
        self.x = 0

    def generator(self):
        self.x += 1
        return self.x

    def test_get_path(self):
        tree = BinaryUserTree(4, lambda: self.generator())
        # This creates the following tree with as indices:
        #           1
        #        /     \
        #     2            3
        #    / \          / \
        #  4     5     6     7
        #  /\    /\    /\    /\
        # 8  9  10 11 12 13 14 15
        self.assertEqual(list(map(lambda x: x.index, tree.get_path(0))), [1, 2, 4, 8])
        self.assertEqual(list(map(lambda x: x.index, tree.get_path(2))), [1, 2, 8, 10])
        self.assertEqual(list(map(lambda x: x.index, tree.get_path(5))), [1, 3, 6, 13])
        self.assertEqual(list(map(lambda x: x.index, tree.get_path(7))), [1, 3, 7, 15])


if __name__ == "__main__":
    unittest.main()
