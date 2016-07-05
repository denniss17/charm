from charm.toolbox.enum import *

OpType = Enum('OR', 'AND', 'ATTR', 'THRESHOLD', 'CONDITIONAL', 'NONE')


class BinaryNode:
    def __init__(self, value, left=None, right=None):
        self.value = value
        self.left = left
        self.right = right

    def getLeft(self):
        return self.left

    def getRight(self):
        return self.right

    def addSubNode(self, left, right):
        # set subNodes appropriately
        self.left = left if left is not None else None
        self.right = right if left is not None else None

    def __str__(self):
        if self.left is None or self.right is None:
            return "%s" % str(self.value)
        else:
            return "%s (%s, %s)" % (str(self.value), str(self.left), str(self.right))


class BinNode(BinaryNode):
    def __init__(self, value, left=None, right=None):
        super(BinNode, self).__init__(value, left, right)
        self.negated = False
        self.index = None
        if isinstance(value, str):
            if value[0] == '!':
                value = value[1:]  # remove but set flag
                self.negated = True
            if value.find('_') != -1:
                val = value.split('_')
                self.index = int(val[1])  # index
                value = val[0]
            self.type = OpType.ATTR
            self.attribute = value

        elif OpType.OR <= value < OpType.NONE:
            self.type = value
            if self.type == OpType.OR:
                self.threshold = 1
            elif self.type == OpType.AND:
                self.threshold = 2
            # elif self.type == OpType.THRESHOLD:
            self.attribute = ''
        else:
            self.type = None
            self.attribute = ''

    def __repr__(self):
        return str(self)

    def __str__(self):
        if self.type == OpType.ATTR:
            if self.negated:
                prefix = '!'
            else:
                prefix = ''
            if self.index is not None:
                postfix = '_' + str(self.index)
            else:
                postfix = ''
            return prefix + self.attribute + postfix
        else:
            left = str(self.left)
            right = str(self.right)

            if self.type == OpType.OR:
                return '(' + left + ' or ' + right + ')'
            elif self.type == OpType.AND:
                return '(' + left + ' and ' + right + ')'
        return None

    def getAttribute(self):
        if self.type == OpType.ATTR:
            if self.negated:
                prefix = '!'
            else:
                prefix = ''
            return prefix + self.attribute
        return

    def getAttributeAndIndex(self):
        if self.type == OpType.ATTR:
            if self.negated:
                prefix = '!'
            else:
                prefix = ''
            if self.index is not None:
                postfix = '_' + str(self.index)
            else:
                postfix = ''

            return prefix + self.attribute + postfix
        return

    def __iter__(self):
        return self

    def __eq__(self, other):
        # print("checking...:", self, str(other))
        if other is None:
            return False
        if type(self) == type(other):
            return self.getAttribute() == other.getAttribute()
        elif type(other) in [str, bytes]:
            return other in self.getAttributeAndIndex()
        elif type(self) in [str, bytes]:
            return self in other.getAttributeAndIndex()
        else:
            raise ValueError('BinNode - invalid comparison.')

    def getNodeType(self):
        return self.type

    # only applies function on leaf nodes
    def traverse(self, function):
        # visit node then traverse left and right
        function(self.type, self)
        if self.left is None:
            return None
        self.left.traverse(function)
        if self.right is None:
            return None
        self.right.traverse(function)
        return None
