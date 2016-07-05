"""
Decentralized Ciphertext-Policy Attribute-Based Encryption Scheme with Fast Decryption
 
| Rao, Y. Sreenivasa and Dutta, Ratna, "Decentralized Ciphertext-Policy Attribute-Based Encryption Scheme with Fast Decryption"
| Published in: Communications and Multimedia Security: 14th IFIP TC 6/TC 11 International Conference
| Available from: http://dx.doi.org/10.1007/978-3-642-40779-6_5

* type:           encryption, multi-authority
* setting:        bilinear groups

:Authors:         Dennis Schroer
:Date:            06/2016
"""

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth

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


class DabeRD13(ABEncMultiAuth):
    """
    Encryption scheme based on
    "Decentralized Ciphertext-Policy Attribute-Based Encryption Scheme with Fast Decryption."
    by Rao and Dutta, http://dx.doi.org/10.1007/978-3-642-40779-6_5.

    >>> group = PairingGroup('SS512')
    >>> dabe = DabeRD13(group)
    >>> public_parameters = dabe.setup()

        Setup the attribute authorities
    >>> attributes1 = ['ONE', 'TWO']
    >>> attributes2 = ['THREE', 'FOUR']
    >>> (public_key1, master_key1) = dabe.authsetup(public_parameters, attributes1)
    >>> (public_key2, master_key2) = dabe.authsetup(public_parameters, attributes2)

        Setup a user and give him some keys
    >>> gid = "bob"
    >>> user_attributes1 = ['ONE', 'TWO']
    >>> user_attributes2 = ['THREE']
    >>> secret_keys1 = dabe.keygen(public_parameters, master_key1, gid, user_attributes1)
    >>> secret_keys2 = dabe.keygen(public_parameters, master_key2, gid, user_attributes2)
    >>> secret_keys = merge_dicts(secret_keys1, secret_keys2)

        Create a random message
    >>> message = group.random(GT)

        Encrypt the message using
        (ONE AND THREE) OR (TWO AND FOUR)
    >>> access_structure = [['ONE', 'THREE'], ['TWO', 'FOUR']]
    >>> public_keys = merge_dicts(public_key1, public_key2)
    >>> cipher_text = dabe.encrypt(public_parameters, public_keys, message, access_structure)

        Decrypt the message
    >>> decrypted_message = dabe.decrypt(public_parameters, secret_keys, cipher_text, gid)
    >>> decrypted_message == message
    True

        Attempt to decrypt an unaccessible message
    >>> access_structure = [['TWO', 'FOUR']]
    >>> cipher_text = dabe.encrypt(public_parameters, public_keys, message, access_structure)
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
        # During system initialization phase, a six tuple GP = (p, G, g, GT, e, H)
        # is chosen as global public parameters. p, e, G and GT are in the group.
        # g is a random generator
        g = self.group.random(G1)
        # H is an hash function which maps strings to group elements
        h = lambda x: self.group.hash(x, G1)
        gp = {'g': g, 'H': h}
        if debug:
            print("Global parameters")
            print(gp)
        return gp

    def authsetup(self, gp, attributes):
        """
        Authority Setup for a given set of attributes.
        :param gp: The global parameters.
        :param attributes: The attributes of the authority.
        """
        pk = {}
        mk = {}
        for attribute in attributes:
            t_a, t_a2 = self.group.random(ZR), self.group.random(ZR)
            p_a, p_a2 = gp['g'] ** t_a, pair(gp['g'], gp['g']) ** t_a2
            pk[attribute] = (p_a, p_a2)
            mk[attribute] = (t_a, t_a2)
        if debug:
            print("Authority keys (pk, mk)")
            print(pk)
            print(mk)
        return pk, mk

    def keygen(self, gp, mk, gid, attributes):
        """
        Generate secret keys for the user with the given global identifier for the attributes.
        :param gp: The global parameters.
        :param mk: The master keys of the attribute authority.
        :param gid: The global identifier of the user.
        :param attributes: The attributes of this attribute authority to generate the secret keys for.
        :raise AssertionError: Raised when one of the attributes is not managed by the authority.
        :return: The secret keys for the attributes for the user.
        """
        sk = {}
        for attribute in attributes:
            assert attribute in mk
            (t_a, t_a2) = mk[attribute]
            sk[attribute] = (gp['g'] ** t_a2) * (gp['H'](gid) ** t_a)
        if debug:
            print("User secret keys")
            print(sk)
        return sk

    def encrypt(self, gp, pk, message, access_structure):
        """
        Encrypt the given message m using the monotone access structure.

        :param pk: The public keys of the authorities which manage the attribute in the access structure.
        :param gp: The global parameters.
        :param message: The message to encrypt.
        :param access_structure: The basis monotone access structure to encrypt the message with.
        :raise AssertionError: Raised when one of the attributes is not in the public keys.
        :return: The ciphertext encrypted with the access structure.
        """
        ct = {'A': access_structure}
        for i in range(0, len(access_structure)):
            authorized_set = access_structure[i]
            s_i = self.group.random(ZR)
            c_1 = 1
            c_2 = gp['g'] ** s_i
            c_3 = 1
            for attribute in authorized_set:
                assert attribute in pk
                (p_a, p_a2) = pk[attribute]
                c_1 *= p_a2
                c_3 *= p_a
            c_1 = message * (c_1 ** s_i)
            c_3 = c_3 ** s_i
            ct[i] = {'c_1': c_1, 'c_2': c_2, 'c_3': c_3}
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
        access_structure = ct['A']
        smallest_set = None
        smallest_set_index = 0
        for i in range(0, len(access_structure)):
            authorized_set = access_structure[i]
            satisfied = True
            for attribute in authorized_set:
                satisfied = satisfied and attribute in sk
            if satisfied and (smallest_set is None or len(authorized_set) < len(smallest_set)):
                smallest_set = authorized_set
                smallest_set_index = i
        if smallest_set is None:
            raise Exception("You don't have the required attributes for decryption!")
        # Calculate Ki, the product of the secret keys of the attributes in the smallest authorized set
        k_i = 1
        for attribute in smallest_set:
            k_i *= sk[attribute]
        # Decrypt
        c_i = ct[smallest_set_index]
        return c_i['c_1'] * (pair(gp['H'](gid), c_i['c_3']) / pair(k_i, c_i['c_2']))

if __name__ == '__main__':
    debug = True

    group = PairingGroup('SS512')
    dabe = DabeRD13(group)
    public_parameters = dabe.setup()
    attributes1 = ['ONE', 'TWO']
    attributes2 = ['THREE', 'FOUR']
    (public_key1, master_key1) = dabe.authsetup(public_parameters, attributes1)
    (public_key2, master_key2) = dabe.authsetup(public_parameters, attributes2)
    gid = "bob"
    user_attributes1 = ['ONE', 'TWO']
    user_attributes2 = ['THREE']
    secret_keys1 = dabe.keygen(public_parameters, master_key1, gid, user_attributes1)
    secret_keys2 = dabe.keygen(public_parameters, master_key2, gid, user_attributes2)
    secret_keys = merge_dicts(secret_keys1, secret_keys2)
    message = group.random(GT)
    access_structure = [['ONE', 'THREE'], ['TWO', 'FOUR']]
    public_keys = merge_dicts(public_key1, public_key2)
    cipher_text = dabe.encrypt(public_parameters, public_keys, message, access_structure)
    decrypted_message = dabe.decrypt(public_parameters, secret_keys, cipher_text, gid)
    print("Decrypted message")
    print(decrypted_message)
    print(decrypted_message == message)

    debug = False

    import doctest
    doctest.testmod()
