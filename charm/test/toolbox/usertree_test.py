import unittest

from charm.toolbox.usertree import BinaryUserTree, BinaryUserTreeNode


class BinaryUserTreeNodeTest(unittest.TestCase):
    def test___eq__(self):
        node1 = BinaryUserTreeNode(34234, 4)
        node2 = BinaryUserTreeNode(34234, 4)
        self.assertEqual(node1, node2)
        node3 = BinaryUserTreeNode(123, 101201, node1, node2)
        node4 = BinaryUserTreeNode(123, 101201, node1, node2)
        node5 = BinaryUserTreeNode(124, 101201, node1, node2)
        node6 = BinaryUserTreeNode(123, 101203, node1, node2)
        node7 = BinaryUserTreeNode(123, 101201)
        self.assertEqual(node3, node4)
        self.assertNotEqual(node3, node5)
        self.assertNotEqual(node3, node6)
        self.assertNotEqual(node3, node7)


class BinaryUserTreeTest(unittest.TestCase):
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
        self.assertEqual(list(map(lambda x: x.index, tree.get_path(2))), [1, 2, 5, 10])
        self.assertEqual(list(map(lambda x: x.index, tree.get_path(5))), [1, 3, 6, 13])
        self.assertEqual(list(map(lambda x: x.index, tree.get_path(7))), [1, 3, 7, 15])

    def test___eq__(self):
        tree1 = BinaryUserTree(4, lambda: self.generator())
        tree2 = BinaryUserTree(4, lambda: self.generator())
        tree2.root = tree1.root
        tree3 = BinaryUserTree(4, lambda: self.generator())
        tree3.root.value = tree1.root.value
        tree3.root.index = tree1.root.index
        tree3.root.left = tree1.root.right
        tree3.root.right = tree1.root.left

        self.assertEqual(tree1, tree2)
        self.assertNotEqual(tree1, tree3)


if __name__ == "__main__":
    unittest.main()
