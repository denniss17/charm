

class BinaryUserTreeNode:
    def __init__(self, value, left=None, right=None):
        self.value = value

class BinaryUserTree:
    """
    A binary user tree is a binary tree in which the leaves are linked to users, while values are assigned to all nodes.
    This can be used for efficient key updates, where the key of a user is composed of the values on the nodes from
    root to the leaf of the user. However, the maximum number of users in the tree is limited
    by the predetermined height of the tree.
    """
    def __init__(self, height):
        self.height = height

    def populate_nodes(self, generator):
        pass
