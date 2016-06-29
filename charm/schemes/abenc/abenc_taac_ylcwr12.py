"""
TAAC: Temporal Attribute-based Access Control for Multi-Authority Cloud Storage Systems
 
| Yang, Kan and Liu, Zhen and Cao, Zhenfu and Jia, Xiaohua and Wong, Duncan S and Ren, Kui
| "TAAC: Temporal Attribute-based Access Control for Multi-Authority Cloud Storage Systems", Appendix D
| Published in: Citeseer 2012
| Available from: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.257.8838&rep=rep1&type=pdf

* type:           encryption
* setting:        bilinear groups

:Authors:         Dennis Schroer
:Date:            06/2016
"""

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.toolbox.usertree import BinaryUserTree

debug = False


def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result


class Taac(ABEncMultiAuth):
    """
    Encryption scheme based on
    "TAAC: Temporal Attribute-based Access Control for Multi-Authority Cloud Storage Systems"
    by Yang, Kan and Liu, Zhen and Cao, Zhenfu and Jia, Xiaohua and Wong, Duncan S and Ren, Kui,
    http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.257.8838&rep=rep1&type=pdf.

    >>> group = PairingGroup('SS512')
    >>> taac = DabeRD13(group)
    >>> public_parameters = dabe.setup()

        Setup the attribute authorities
    >>> attributes1 = ['ONE', 'TWO']
    >>> attributes2 = ['THREE', 'FOUR']
    >>> (public_key1, master_key1) = taac.authsetup(public_parameters, attributes1)
    >>> (public_key2, master_key2) = taac.authsetup(public_parameters, attributes2)

        Setup a user and give him some keys
    >>> gid = "bob"
    >>> user_attributes1 = ['ONE', 'TWO']
    >>> user_attributes2 = ['THREE']
    >>> secret_keys1 = taac.keygen(public_parameters, master_key1, gid, user_attributes1)
    >>> secret_keys2 = taac.keygen(public_parameters, master_key2, gid, user_attributes2)
    >>> secret_keys = merge_dicts(secret_keys1, secret_keys2)

        Create a random message
    >>> message = group.random(GT)

        Encrypt the message using
        (ONE AND THREE) OR (TWO AND FOUR)
    >>> access_structure = [['ONE', 'THREE'], ['TWO', 'FOUR']]
    >>> public_keys = merge_dicts(public_key1, public_key2)
    >>> cipher_text = taac.encrypt(public_keys, public_parameters, message, access_structure)

        Decrypt the message
    >>> decrypted_message = taac.decrypt(public_parameters, secret_keys, cipher_text, gid)
    >>> decrypted_message == message
    True

        Attempt to decrypt an unaccessible message
    >>> access_structure = [['TWO', 'FOUR']]
    >>> cipher_text = dabe.encrypt(public_keys, public_parameters, message, access_structure)
    >>> decrypted_message = dabe.decrypt(public_parameters, secret_keys, cipher_text, gid)
    Traceback (most recent call last):
     ...
    Exception: You don't have the required attributes for decryption!
    """

    def __init__(self, group):
        """
        Initialize this ABE scheme.
        :param group: The bilinear group to use.
        """
        ABEncMultiAuth.__init__(self)
        self.util = SecretUtil(group, verbose=False)
        self.group = group

    def setup(self):
        """Global Setup"""
        # During system initialization phase, a six tuple GP = (p, g, H)
        # is chosen as global public parameters. p and G are in the group.
        # g is a random generator
        g = self.group.random(G1)
        # H is an hash function which maps strings to group elements
        h = lambda x: self.group.hash(x, G1)
        gp = {'g': g, 'h': h}
        if debug:
            print("Global parameters")
            print(gp)
        return gp

    def authsetup(self, gp, attributes, height):
        """
        Authority Setup for a given set of attributes.
        :param gp: The global parameters.
        :param attributes: The attributes of the authority.
        :param height: The height of the binary user trees to create. The number of allowed users is 2^height.
        """
        pk = {}
        mk = {}
        states = {}
        for attribute in attributes:
            # Choose two random exponents a, b from Zp
            a, b = self.group.random(ZR), self.group.random(ZR)
            # Create a binary tree with given height and random elements from G
            tree = BinaryUserTree(height, lambda: self.group.random(G1))
            pk[attribute] = {'e(g,g)^a': pair(gp['g'], gp['g']) ** a, 'g^b': gp['g'] ** b}
            mk[attribute] = {'a': a, 'b': b, 'tree': tree}
            # States of the attributes, each state contains a counter a mapping of user id to leaf index
            states[attribute] = {'h': height, 'ctr': 0, 'list': {}}
        pk['H'] = lambda x, t: self.group.hash((x, t), G1)
        if debug:
            print("Authority setup")
            print(pk)
            print(mk)
            print(states)
        return pk, mk, states

    def keygen(self, gp, mk, states, gid, attributes):
        """
        Generate secret keys for the user with the given global identifier for the attributes.
        :param gp: The global parameters.
        :param mk: The master keys of the attribute authority.
        :param states: The states of the attributes
        :param gid: The global identifier of the user.
        :param attributes: The attributes of this attribute authority to generate the secret keys for.
        :raise AssertionError: Raised when one of the attributes is not managed by the authority.
        :return: The secret keys for the attributes for the user.
        """
        sk = {}
        for attribute in attributes:
            if gid in states[attribute]['list']:
                # Use the existing leaf
                leaf_index = states[attribute]['list'][gid]
            else:
                # Update attribute state, assigning the leftmost empty leaf to the user
                assert states[attribute]['ctr'] < 2 ** (states[attribute]['h'] - 1)
                leaf_index = states[attribute]['ctr']
                states[attribute]['list'][gid] = leaf_index
                states[attribute]['ctr'] += 1
            # Get the path to the leaf
            path = mk[attribute]['tree'].get_path(leaf_index)
            sk[attribute] = {}
            for v in path:
                sk[attribute][v.index] = (gp['g'] ** mk[attribute]['a']) * (
                gp['H'](gid) ** mk[attribute]['b']) * v.value
        if debug:
            print("User secret keys")
            print(sk)
        return sk

    def updatekeygen(self, gp, pk, mk, rl, t, attributes):
        """
        Generate update keys for timeslot t, where keys are only updated for users not in the revocation list rl.
        :param gp: The global parameters.
        :param pk: The public key of the authority.
        :param mk: The master key of the authority.
        :param rl: The revocation list for the attributes containing user ids of revoked users.
        :param t: The timeslot.
        :param attributes: The attributes to generate update keys for.
        :return: A set of update keys for the attributes.
        """
        uk = {}
        for attribute in attributes:
            nodes = self.updatekeynodes(attribute, mk, rl)
            uk[attribute] = {}
            for v in nodes:
                exponent = self.group.random(ZR)
                e_v = v.value * (pk['H'](attribute, t) ** exponent)
                e_v2 = gp['g'] ** exponent
                uk[attribute][v.index] = (e_v, e_v2)
        return uk

    def updatekeynodes(self, attribute, mk, rl):
        # For now simply return the root
        return [mk[attribute]['tree'].root]

    def encrypt(self, pk, gp, message, access_policy, t):
        """
        Encrypt the message under the given access policy for the given time period.
        :param pk: The public keys of the attribute authorities.
        :param gp: The global parameters.
        :param message: The message to encrypt.
        :param access_policy: The access policy to encrypt under.
        :param t: The time period to encrypt for.
        :return: The encrypted message.
        """
        # Select a random secret
        s = self.group.random(ZR)
        # Parse the policy
        policy = self.util.createPolicy(access_policy)
        # Calculate shares of the secret as dict from attribute to share
        vshares = self.util.calculateSharesDict(s, policy)
        ushares = self.util.calculateSharesDict(group.init(ZR, 0), policy)
        # Encrypt the message
        c = message * pair(gp['g'], gp['g']) ** s
        ct = {'A': access_policy, 'C': c}
        for attribute in vshares.keys():
            r = self.group.random(ZR)
            c_1 = (pair(gp['g'], gp['g']) ** vshares[attribute]) * (pk[attribute]['e(g,g)^a'] ** r)
            c_2 = (gp['g'] ** ushares[attribute]) * (pk[attribute]['g^b'] ** r)
            c_3 = gp['g'] ** r
            c_4 = pk['H'](attribute, t) ** r
            ct[attribute] = {'c_1': c_1, 'c_2': c_2, 'c_3': c_3, 'c_4': c_4}
        if debug:
            print("Message")
            print(message)
            print("Ciphertext")
            print(ct)
        return ct

    def decrypt(self, gp, sk, ct, gid):
        """
        Decrypt the ciphertext using the user's secret keys.

        :param gp: The global parameters.
        :param sk: The secret key of the user.
        :param ct: The ciphertext to decrypt.
        :param gid: The identifier of the user.
        :raise Exception: Raised when the secret keys of the user do not satisfy the access structure.
        :return: The decrypted message.
        """
        # Get the smallest authorized set which can be satisfied with the secret keys
        pass

    def decryption_key_computation(self, sk, uk):



if __name__ == '__main__':
    debug = True

    group = PairingGroup('SS512')
    taac = Taac(group)
    public_parameters = taac.setup()
    attributes1 = ['ONE', 'TWO']
    attributes2 = ['THREE', 'FOUR']
    (public_key1, master_key1) = taac.authsetup(public_parameters, attributes1)
    (public_key2, master_key2) = taac.authsetup(public_parameters, attributes2)
    gid = "bob"
    user_attributes1 = ['ONE', 'TWO']
    user_attributes2 = ['THREE']
    secret_keys1 = taac.keygen(public_parameters, master_key1, gid, user_attributes1)
    secret_keys2 = taac.keygen(public_parameters, master_key2, gid, user_attributes2)
    secret_keys = merge_dicts(secret_keys1, secret_keys2)
    message = group.random(GT)
    access_structure = [['ONE', 'THREE'], ['TWO', 'FOUR']]
    public_keys = merge_dicts(public_key1, public_key2)
    cipher_text = taac.encrypt(public_keys, public_parameters, message, access_structure)
    decrypted_message = taac.decrypt(public_parameters, secret_keys, cipher_text, gid)
    print("Decrypted message")
    print(decrypted_message)
    print(decrypted_message == message)

    debug = False

    import doctest

    doctest.testmod()
