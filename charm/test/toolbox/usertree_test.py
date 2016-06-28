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
        # This creates the following tree:
        #           1
        #        /     \
        #     2            9
        #    / \          / \
        #  3     6     10    13
        #  /\    /\    /\    /\
        # 4  5  7  8  11 12 14 15
        self.assertEqual(list(map(lambda x: x.value, tree.get_path(0))), [1, 2, 3, 4])
        self.assertEqual(list(map(lambda x: x.value, tree.get_path(2))), [1, 2, 6, 7])
        self.assertEqual(list(map(lambda x: x.value, tree.get_path(5))), [1, 9, 10, 12])
        self.assertEqual(list(map(lambda x: x.value, tree.get_path(7))), [1, 9, 13, 15])


if __name__ == "__main__":
    unittest.main()
