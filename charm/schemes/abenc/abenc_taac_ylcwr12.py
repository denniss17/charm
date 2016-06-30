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

        Setup
    >>> group = PairingGroup('SS512')
    >>> taac = Taac(group)
    >>> public_parameters = taac.setup()

        Authority setup
    >>> attributes1 = ['ONE', 'TWO']
    >>> attributes2 = ['THREE', 'FOUR']
    >>> (public_key1, master_key1, states1) = taac.authsetup(public_parameters, attributes1, 4)
    >>> (public_key2, master_key2, states2) = taac.authsetup(public_parameters, attributes2, 4)

        User secret keys
    >>> gid = "bob"
    >>> user_attributes1 = ['ONE', 'TWO']
    >>> user_attributes2 = ['THREE']
    >>> secret_keys1 = taac.keygen(public_parameters, master_key1, states1, gid, user_attributes1)
    >>> secret_keys2 = taac.keygen(public_parameters, master_key2, states2, gid, user_attributes2)

        Encrypt for time period 1
    >>> message = group.random(GT)
    >>> access_policy = '(ONE or THREE) and (TWO or FOUR)'
    >>> public_keys = merge_dicts(public_key1, public_key2)
    >>> cipher_text = taac.encrypt(public_keys, public_parameters, message, access_policy, 1)

        Generate update keys for time period 1
    >>> update_keys1 = taac.generate_update_keys(public_parameters, public_key1, master_key1, {}, 1, attributes1)
    >>> update_keys2 = taac.generate_update_keys(public_parameters, public_key2, master_key2, {}, 1, attributes2)

        Calculate decryption keys
    >>> decryption_keys1 = taac.decryption_keys_computation(secret_keys1, update_keys1)
    >>> decryption_keys2 = taac.decryption_keys_computation(secret_keys2, update_keys2)
    >>> decryption_keys = Taac.merge_timed_keys(decryption_keys1, decryption_keys2)

        Decrypt the message
    >>> decrypted_message = taac.decrypt(public_parameters, decryption_keys, cipher_text, gid)
    >>> decrypted_message == message
    True

        Attempt to decrypt an unaccessible message
    >>> access_policy = 'FOUR and TWO'
    >>> cipher_text = taac.encrypt(public_keys, public_parameters, message, access_policy, 1)
    >>> decrypted_message = taac.decrypt(public_parameters, decryption_keys, cipher_text, gid)
    Traceback (most recent call last):
     ...
    Exception: You don't have the required attributes for decryption!

        Attempt to decrypt a message of another time period
    >>> access_policy = '(ONE or THREE) and (TWO or FOUR)'
    >>> cipher_text = taac.encrypt(public_keys, public_parameters, message, access_policy, 2)
    >>> decrypted_message = taac.decrypt(public_parameters, decryption_keys, cipher_text, gid)
    Traceback (most recent call last):
     ...
    Exception: This ciphertext was encrypted for another time period!
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
        gp = {'g': g, 'H': h}
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
        :param states: The states of the attribute
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
                if states[attribute]['ctr'] >= 2 ** (states[attribute]['h'] - 1):
                    raise Exception("The binary user tree of %s is full (height=%d, max=%d)!" %
                                    (attribute, states[attribute]['h'], 2 ** (states[attribute]['h'] - 1)))
                leaf_index = states[attribute]['ctr']
                states[attribute]['list'][gid] = leaf_index
                states[attribute]['ctr'] += 1
            # Get the path to the leaf
            path = mk[attribute]['tree'].get_path(leaf_index)
            sk[attribute] = {}
            for v in path:
                k_xv = (gp['g'] ** mk[attribute]['a']) * (gp['H'](gid) ** mk[attribute]['b']) * v.value
                sk[attribute][v.index] = k_xv
        if debug:
            print("User secret key")
            print(attributes)
            print(sk)
        return sk

    def generate_update_key(self, gp, pk, mk, rl, t, attribute):
        """
        Generate update keys for timeslot t for a single attribute,
        where keys are only updated for users not in the revocation list rl.
        :param gp: The global parameters.
        :param pk: The public key of the authority.
        :param mk: The master key of the authority.
        :param rl: The revocation list for the attributes containing user ids of revoked users.
        :param t: The timeslot.
        :param attribute: The attribute to generate update keys for.
        :return: A set of update keys for the attribute.
        """
        uk = {}
        nodes = self.updatekeynodes(attribute, mk, rl)
        for v in nodes:
            exponent = self.group.random(ZR)
            e_v = v.value * (pk['H'](attribute, t) ** exponent)
            e_v2 = gp['g'] ** exponent
            uk[v.index] = (e_v, e_v2)
        return uk

    def generate_update_keys(self, gp, pk, mk, rls, t, attributes):
        """
        Generate update keys for timeslot t for a list of attributes,
        where keys are only updated for users not in the revocation list rls[attribute].
        :param gp: The global parameters.
        :param pk: The public key of the authority.
        :param mk: The master key of the authority.
        :param rls: The revocation lists for the attributes containing user ids of revoked users.
        If a revocation list is not present for an attribute, it is assumed to be empty.
        :param t: The timeslot.
        :param attributes: The list of attributes to generate update keys for.
        :return: A set of update keys for the attributes.
        """
        uks = {'t': t, 'keys': {}}
        for attribute in attributes:
            rl = rls[attribute] if attribute in rls else []
            uks['keys'][attribute] = self.generate_update_key(gp, pk, mk, rl, t, attribute)
        if debug:
            print("Update keys")
            print(uks)
        return uks

    def updatekeynodes(self, attribute, mk, rl):
        """
        Determine the minimum set of nodes to update covering all non-revoked uses.
        :param attribute: The attribute to determine the set of nodes for.
        :param mk: The master key of the attribute authority.
        :param rl: The revocation list.
        :return: The minimum set of nodes to update.
        """
        # For now simply return the root
        return [mk[attribute]['tree'].root]

    @staticmethod
    def merge_timed_keys(*timed_keys):
        """
        Merge timed keys, like the update keys or the decryption keys.
        :param timed_keys: A list of timed keys to merge.
        :return: The merged keys.

        >>> Taac.merge_timed_keys({'t': 1, 'keys': {'a': 'A'}}, {'t': 1, 'keys': {'b': 'B'}})
        {'t': 1, 'keys': {'a': 'A', 'b': 'B'}}

        >>> Taac.merge_timed_keys({'t': 1, 'keys': {'a': 'A'}}, {'t': 2, 'keys': {'b': 'B'}})
        Traceback (most recent call last):
        ...
        AssertError: Keys can not be merged as the time period differs.
        """
        result = {'keys': {}}
        for authority_timed_keys in timed_keys:
            assert 't' not in result or result['t'] == authority_timed_keys['t'], \
                "Keys can not be merged as the time period differs."
            result['t'] = authority_timed_keys['t']
            result['keys'].update(authority_timed_keys['keys'])
        if debug:
            print("Merged keys")
            print(result)
        return result

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
        ushares = self.util.calculateSharesDict(self.group.init(ZR, 0), policy)
        # Encrypt the message
        c = message * pair(gp['g'], gp['g']) ** s
        ct = {'A': access_policy, 't': t, 'c': c}
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

    def decryption_key_computation(self, sk, uk):
        """
        Calculate the decryption key for a single attribute.
        :param sk: The user's secret key part for the attribute.
        :param uk: The update key part for the attribute.
        :return: The decryption key if the user possesses the attribute at the time, None otherwise.
        """
        # Secret keys
        # for v in path:
        #    k_xv = (gp['g'] ** mk[attribute]['a']) * (gp['H'](gid) ** mk[attribute]['b']) * v.value
        #    sk[v.index] = k_xv
        # Update keys
        # for v in nodes:
        #    exponent = self.group.random(ZR)
        #    e_v = v.value * (pk['H'](attribute, t) ** exponent)
        #    e_v2 = gp['g'] ** exponent
        #    uk[v.index] = (e_v, e_v2)
        # If the user possesses the attribute at t, there exists a unique v_x such that v_x in path(u) and in N_x
        # (the set of updated nodes in the update key)
        # We try to find this node
        intersection = set(sk.keys()) & set(uk.keys())
        if len(intersection) > 0:
            # Node is found
            v_x = intersection.pop()
            # Extract keys
            k_x = sk[v_x]
            (e_v, e_v2) = uk[v_x]
            # Calculate update key
            return k_x / e_v, e_v2
        else:
            # Node is not found, so the user does not possess this attribute at time t
            return None

    def decryption_keys_computation(self, sks, uks):
        dks = {'t': uks['t'], 'keys': {}}
        for attribute in sks:
            dk = self.decryption_key_computation(sks[attribute], uks['keys'][attribute])
            if dk is not None:
                dks['keys'][attribute] = dk
        if debug:
            print("Decryption keys")
            print(dks)
        return dks

    def decrypt(self, gp, dk, ct, gid):
        """
        Decrypt the ciphertext using the user's secret keys.

        :param gp: The global parameters.
        :param dk: The decryption keys of the user as dict from attribute to key.
        :param ct: The ciphertext to decrypt.
        :param gid: The identifier of the user.
        :raise Exception: Raised when the secret keys of the user do not satisfy the access structure.
        :return: The decrypted message.
        """
        if ct['t'] != dk['t']:
            raise Exception("This ciphertext was encrypted for another time period!")

        # Get the smallest authorized set which can be satisfied with the secret keys
        policy = self.util.createPolicy(ct['A'])
        coefficients = self.util.getCoefficients(policy)
        pruned_list = self.util.prune(policy, dk['keys'].keys())

        if not pruned_list:
            raise Exception("You don't have the required attributes for decryption!")

        product = self.group.init(GT, 1)
        for i in range(len(pruned_list)):
            x = pruned_list[i].getAttribute()  # without the underscore
            y = pruned_list[i].getAttributeAndIndex()  # with the underscore
            c_i = (ct[y]['c_1'] * pair(gp['H'](gid), ct[y]['c_2'])) / \
                  (pair(dk['keys'][x][0], ct[y]['c_3']) * pair(dk['keys'][x][1], ct[y]['c_4']))
            product *= c_i ** coefficients[y]
        return ct['c'] / product


if __name__ == '__main__':
    debug = True

    # Setup
    group = PairingGroup('SS512')
    taac = Taac(group)
    public_parameters = taac.setup()

    # Authority setup
    attributes1 = ['ONE', 'TWO']
    attributes2 = ['THREE', 'FOUR']
    (public_key1, master_key1, states1) = taac.authsetup(public_parameters, attributes1, 4)
    (public_key2, master_key2, states2) = taac.authsetup(public_parameters, attributes2, 4)

    # User secret keys
    gid = "bob"
    user_attributes1 = ['ONE', 'TWO']
    user_attributes2 = ['THREE']
    secret_keys1 = taac.keygen(public_parameters, master_key1, states1, gid, user_attributes1)
    secret_keys2 = taac.keygen(public_parameters, master_key2, states2, gid, user_attributes2)

    # Encrypt for time period 1
    message = group.random(GT)
    access_policy = '(ONE or THREE) and (TWO or FOUR)'
    public_keys = merge_dicts(public_key1, public_key2)
    cipher_text = taac.encrypt(public_keys, public_parameters, message, access_policy, 1)

    # Generate update keys for time period 1
    update_keys1 = taac.generate_update_keys(public_parameters, public_key1, master_key1, [], 1, attributes1)
    update_keys2 = taac.generate_update_keys(public_parameters, public_key2, master_key2, [], 1, attributes2)

    # Calculate decryption keys
    decryption_keys1 = taac.decryption_keys_computation(secret_keys1, update_keys1)
    decryption_keys2 = taac.decryption_keys_computation(secret_keys2, update_keys2)
    decryption_keys = Taac.merge_timed_keys(decryption_keys1, decryption_keys2)

    # Decrypt the message
    decrypted_message = taac.decrypt(public_parameters, decryption_keys, cipher_text, gid)
    print("Decrypted message")
    print(decrypted_message)
    print(decrypted_message == message)
