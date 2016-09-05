from charm.toolbox.node import BinaryNode


class BinaryUserTreeNode(BinaryNode):
    def __init__(self, index, value, left=None, right=None):
        super(BinaryUserTreeNode, self).__init__(value, left, right)
        self.index = index

    def is_leaf(self):
        return self.left is None and self.right is None

    def __str__(self):
        if self.left is None or self.right is None:
            return "%d:%s" % (self.index, str(self.value))
        else:
            return "%d:%s (%s, %s)" % (self.index, str(self.value), str(self.left), str(self.right))

    def __eq__(self, other):
        return isinstance(other, BinaryUserTreeNode) \
               and self.index == other.index \
               and self.value == other.value \
               and self.left == other.left \
               and self.right == other.right

    def __hash__(self):
        return hash((self.index, self.value, self.left, self.right))


class BinaryUserTree:
    """
    A binary user tree is a binary tree in which the leaves are linked to users, while values are assigned to all nodes.
    This can be used for efficient key updates, where the key of a user is composed of the values on the nodes from
    root to the leaf of the user. However, the maximum number of users in the tree is limited
    by the predetermined height of the tree.

    The root node has level 0, the leaves have level height-1
    """

    def __init__(self, height, generator):
        self.height = height
        self.root = self.populate_tree(generator, height)

    def populate_tree(self, generator, height, index=1):
        """
        Create a tree of given height and populate the nodes
        and leaves with values returned by the generator function.
        """
        node = BinaryUserTreeNode(index, generator())
        if height > 1:
            node.addSubNode(self.populate_tree(generator, height - 1, index * 2),
                            self.populate_tree(generator, height - 1, index * 2 + 1))
        return node

    def get_leaf(self, index):
        pass

    def get_path(self, index):
        """
        Get the path from the root node to the leaf with given index.
        The leftmost leaf has index 0, the rightmost leaf has index 2^(height-1)-1
        """
        return self._get_path(index, self.root, self.height)

    def __str__(self):
        return "BinaryUserTree %s" % str(self.root)

    def __eq__(self, other):
        return isinstance(other, BinaryUserTree) \
               and self.height == other.height \
               and self.root == other.root

    def _get_path(self, index, node, height):
        if height == 1:
            return [node]
        else:
            # The number of leaves, for height 4 this is 8 (2^3)
            size = 2 ** (height - 1)
            if index < size / 2:
                # Leaf is in the left side of the tree
                return [node] + self._get_path(index, node.left, height - 1)
            else:
                # Leaf is in the right side of the tree
                return [node] + self._get_path(index - (size / 2), node.right, height - 1)
