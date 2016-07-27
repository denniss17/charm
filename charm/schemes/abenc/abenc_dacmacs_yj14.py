"""
Kan Yang, Xiaohua Jia 
 
| From: DAC-MACS: Effective Data Access Control for Multi-Authority Cloud Storage Systems 
| Published in:  Security for Cloud Storage Systems  - SpringerBriefs in Computer Science 2014
| Available From: http://link.springer.com/chapter/10.1007/978-1-4614-7873-7_4
| Notes: 

* type:           ciphertext-policy attribute-based encryption (public key)
* setting:        Pairing

:Authors:   artjomb
:Date:      07/2014
"""
import re
from functools import reduce

from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.toolbox.pairinggroup import PairingGroup, G1, GT, pair
from charm.toolbox.secretutil import SecretUtil


def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result


class DACMACS(ABEncMultiAuth):
    def __init__(self, group):
        """
        Creates a new DACMACS instance.
        :param group: The pairing group to use.


        Default use case
        >>> group = PairingGroup('SS512')
        >>> dacmacs = DACMACS(group)
        >>> GPP, GMK = dacmacs.setup()
        >>> authority1 = "A1"
        >>> authority2 = "A2"
        >>> authority1_attributes = ["ONE@A1", "TWO@A1"]
        >>> authority2_attributes = ["THREE@A2", "FOUR@A2"]
        >>> authority1_public, authority1_secret = dacmacs.authsetup(GPP, authority1_attributes)
        >>> authority2_public, authority2_secret = dacmacs.authsetup(GPP, authority2_attributes)
        >>> alice_global_public, alice_global_secret = dacmacs.register_user(GPP)
        >>> alice_secret1 = dacmacs.keygen(GPP, authority1_secret, authority1_public, ["ONE@A1", "TWO@A1"], alice_global_secret['cert'])
        >>> alice_secret2 = dacmacs.keygen(GPP, authority2_secret, authority2_public, ["THREE@A2"], alice_global_secret['cert'])

        Encrypt a message
        >>> k = group.random(GT)
        >>> policy_str = '((ONE@A1 or THREE@A2) and (TWO@A1 or FOUR@A2))'
        >>> public_keys = {authority1: authority1_public, authority2: authority2_public}
        >>> CT = dacmacs.encrypt(GPP, public_keys, k, policy_str)
        >>> secret_keys = {authority1: alice_secret1, authority2: alice_secret2}
        >>> TK = dacmacs.generate_token(GPP, CT, alice_global_public, secret_keys)
        >>> PT = dacmacs.decrypt(CT, TK, alice_global_secret)
        >>> k == PT
        True

        >>> # Central setup
        >>> group = PairingGroup('SS512')
        >>> dacmacs = DACMACS(group)
        >>> GPP, GMK = dacmacs.setup()
        >>> # Authorities setup
        >>> authority1 = "A1"
        >>> authority2 = "A2"
        >>> authority1_attributes = ["ONE@A1", "TWO@A1"]
        >>> authority2_attributes = ["THREE@A2", "FOUR@A2"]
        >>> authority1_public, authority1_secret = dacmacs.authsetup(GPP, authority1_attributes)
        >>> authority2_public, authority2_secret = dacmacs.authsetup(GPP, authority2_attributes)
        >>> # Create user 'alice'
        >>> alice_global_public, alice_global_secret = dacmacs.register_user(GPP)
        >>> alice_secret1 = dacmacs.keygen(GPP, authority1_secret, authority1_public, ["ONE@A1", "TWO@A1"],
        ...                                alice_global_secret['cert'])
        >>> alice_secret2 = dacmacs.keygen(GPP, authority2_secret, authority2_public, ["THREE@A2"],
        ...                                alice_global_secret['cert'])
        >>> alice_secret_keys = {authority1: alice_secret1, authority2: alice_secret2}
        >>> # Create user 'bob'
        >>> bob_global_public, bob_global_secret = dacmacs.register_user(GPP)
        >>> bob_secret1 = dacmacs.keygen(GPP, authority1_secret, authority1_public, ["ONE@A1", "TWO@A1"],
        ...                                bob_global_secret['cert'])
        >>> bob_secret2 = dacmacs.keygen(GPP, authority2_secret, authority2_public, ["THREE@A2"],
        ...                               bob_global_secret['cert'])
        >>> bob_secret_keys = {authority1: bob_secret1, authority2: bob_secret2}
        >>> # Encrypt a message
        >>> k = group.random(GT)
        >>> policy_str = '((ONE@A1 or THREE@A2) and (TWO@A1 or FOUR@A2))'
        >>> public_keys = {authority1: authority1_public, authority2: authority2_public}
        >>> CT = dacmacs.encrypt(GPP, public_keys, k, policy_str)
        >>> # Calculate tokens
        >>> TK_alice = dacmacs.generate_token(GPP, CT, alice_global_public, alice_secret_keys)
        >>> TK_bob = dacmacs.generate_token(GPP, CT, bob_global_public, bob_secret_keys)
        >>> # Attempt to decrypt
        >>> PT_alice = dacmacs.decrypt(CT, TK_alice, alice_global_secret)
        >>> PT_bob = dacmacs.decrypt(CT, TK_bob, bob_global_secret)
        >>> PT_alice == k
        True
        >>> PT_bob == k
        True
        >>> # Revoke "ONE@A1" from bob
        >>> revoked_attribute = "ONE@A1"
        >>> KUK, CUK = dacmacs.update_keygen(GPP, authority1_secret, authority1_public, revoked_attribute,
        ...                          {'alice': alice_global_public})
        >>> # Send the key update key only to alice
        >>> dacmacs.sk_update(alice_secret_keys, revoked_attribute, KUK['alice'])
        >>> # Update the ciphertext
        >>> dacmacs.ct_update(GPP, CT, revoked_attribute, CUK)
        >>> # Calculate tokens
        >>> TK_alice = dacmacs.generate_token(GPP, CT, alice_global_public, alice_secret_keys)
        >>> TK_bob = dacmacs.generate_token(GPP, CT, bob_global_public, bob_secret_keys)
        >>> # Attempt to decrypt
        >>> PT_alice = dacmacs.decrypt(CT, TK_alice, alice_global_secret)
        >>> PT_bob = dacmacs.decrypt(CT, TK_bob, bob_global_secret)
        >>> PT_alice == k
        True
        >>> PT_bob == k
        False
        """
        super().__init__()
        self.util = SecretUtil(group, verbose=False)  # Create Secret Sharing Scheme
        self.group = group  # type: PairingGroup

    def setup(self):
        """Global Setup (executed by CA)"""
        # In global setup, a bilinear group G of prime order p is chosen
        # The global public parameters, GP and p, and a generator g of G. A random oracle H maps global identities GID to elements of G

        # group contains
        # the prime order p is contained somewhere within the group object
        g = self.group.random(G1)
        # The oracle that maps global identities GID onto elements of G
        # H = lambda str: g** group.hash(str)
        H = lambda x: self.group.hash(x, G1)
        a = self.group.random()
        g_a = g ** a
        GPP = {'g': g, 'g^a': g_a, 'H': H}
        GMK = {'a': a}

        return GPP, GMK

    def register_user(self, GPP):
        """Generate user keys (executed by the user)."""
        g = GPP['g']
        u = self.group.random()
        z = self.group.random()
        # GPK_uid = g ** u
        # GSK_uid = z
        g_u = g ** u
        g_z = g ** (1 / z)

        return g_u, {'z': z, 'cert': {'g^(1/z)': g_z, 'u': u}}  # (public, private)

    def authsetup(self, GPP, attributes, secret_keys=None, public_keys=None):
        """Generate attribute authority keys (executed by attribute authority)"""
        if secret_keys is None or public_keys is None:
            alpha = self.group.random()
            beta = self.group.random()
            gamma = self.group.random()
            secret_keys = {
                'alpha': alpha,
                'beta': beta,
                'gamma': gamma,
                'attr': {}
            }
            public_keys = {
                'e(g,g)^alpha': pair(GPP['g'], GPP['g']) ** alpha,
                'g^(1/beta)': GPP['g'] ** (1 / beta),
                'g^(gamma/beta)': GPP['g'] ** (gamma / beta),
                'attr': {}
            }
        for attribute in attributes:
            if attribute in secret_keys['attr'] and attribute in public_keys['attr']:
                continue
            version_key = self.group.random()  # random or really 'choose' ?
            h = GPP['H'](attribute)
            pk = ((GPP['g'] ** version_key) * h) ** secret_keys['gamma']
            secret_keys['attr'][attribute] = version_key
            public_keys['attr'][attribute] = pk
        return public_keys, secret_keys

    def keygen(self, GPP, authority_secret, authority_public, attributes, user_cert):
        """
        Generate user keys for specific attributes of an attribute authority (executed on attribute authority).
        :param GPP:
        :param authority_secret:
        :param authority_public:
        :param attributes:
        :param user_public:
        :return:
        """
        t = self.group.random()

        USK = dict()
        USK['K'] = \
            (user_cert['g^(1/z)'] ** authority_secret['alpha']) * \
            (GPP['g^a'] ** user_cert['u']) * \
            (GPP['g^a'] ** (t / authority_secret['beta']))
        USK['L'] = user_cert['g^(1/z)'] ** (authority_secret['beta'] * t)
        USK['R'] = GPP['g^a'] ** t
        USK['AK'] = {}
        for attribute in attributes:
            USK['AK'][attribute] = (
                                       user_cert['g^(1/z)'] ** (
                                           authority_secret['beta'] * authority_secret['gamma'] * t)) * (
                                       authority_public['attr'][attribute] ** (
                                           authority_secret['beta'] * user_cert['u']))
        return USK

    def encrypt(self, GPP, pks, m, policy_string):
        """Generate the cipher-text from the content(-key) and a policy (executed by the content owner)"""
        # GPP are global parameters
        # k is the content key (group element based on AES key)
        # policy_str is the policy string
        # authority is the authority tuple

        policy = self.util.createPolicy(policy_string)
        secret = self.group.random()
        shares = self.util.calculateSharesList(secret, policy)
        shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in shares])

        C = m * (reduce(lambda x, y: x * y['e(g,g)^alpha'], pks.values(), 1) ** secret)
        C1 = GPP['g'] ** secret
        # I dont know if this is correct: the paper states this incorrect
        C2 = {authority_name: pks[authority_name]['g^(1/beta)'] ** secret for authority_name in pks.keys()}
        # C2 = reduce(lambda x, y: x * y['g^(1/beta)'], pks.values(), self.group.init(1, GT)) ** secret
        Ci = {}
        D1 = {}
        D2 = {}

        for attr, s_share in shares.items():
            attribute, authority, _ = self.unpack_attribute(attr)
            attribute_name = "%s@%s" % (attribute, authority)
            r_i = self.group.random()
            attrPK = pks[authority]['attr'][attribute_name]
            Ci[attr] = (GPP['g^a'] ** s_share) * ~(attrPK ** r_i)
            D1[attr] = pks[authority]['g^(1/beta)'] ** r_i
            D2[attr] = ~(pks[authority]['g^(gamma/beta)'] ** r_i)

        return {'C': C, 'C1': C1, 'C2': C2, 'Ci': Ci, 'D1': D1, 'D2': D2, 'policy': policy_string}

    def generate_token(self, GPP, CT, GPK, SK):
        """
        Generates a token using the user's attribute secret keys to offload
        the decryption process (executed by cloud provider)
        :param GPP: The global public parameters
        :param CT: The cipertext
        :param GPK: The global public key of the user
        :param SK: The secret keys of the user
        :raise Exception: Raised when the attributes do not satisfy the policy
        :return: A decryption token
        """
        user_attributes = reduce(lambda x, y: x + list(y['AK'].keys()), SK.values(), [])
        policy = self.util.createPolicy(CT['policy'])
        pruned = self.util.prune(policy, user_attributes)
        if not pruned:
            raise Exception("The attributes do not satisfy the policy")
        coeffs = self.util.getCoefficients(policy)

        token = 1
        n_a = len(SK)

        for authority_name in SK:
            dividend = pair(CT['C1'], SK[authority_name]['K']) * ~pair(SK[authority_name]['R'],
                                                                       CT['C2'][authority_name])
            divisor = 1

            for attr in pruned:
                attribute_with_index = attr.getAttributeAndIndex()
                attribute, authority, _ = self.unpack_attribute(attribute_with_index)
                if authority == authority_name:
                    attribute_name = "%s@%s" % (attribute, authority)
                    temp = \
                        pair(CT['Ci'][attribute_with_index], GPK) * \
                        pair(CT['D1'][attribute_with_index], SK[authority]['AK'][attribute_name]) * \
                        pair(CT['D2'][attribute_with_index], SK[authority]['L'])
                    divisor *= temp ** (coeffs[attribute_with_index] * n_a)
            token *= dividend / divisor

        return token

    def decrypt(self, CT, TK, GSK):
        """
        Decrypts the content(-key) from the cipher-text using the token
        and the user secret key (executed by user/content consumer)
        :param CT: The ciphertext
        :param TK: The decryption token
        :param GSK: The user global secret keys
        :return:
        """
        return CT['C'] / (TK ** GSK['z'])

    def update_keygen(self, GPP, authority_secret, authority_public, attribute, GPKs):
        """
        Revoke an attribute from a user and generate update keys for users and cloud providers
        (executed by attribute authority)
        :param GPP: The global public parameters
        :param authority_secret: The secret keys of the authority
        :param authority_public: The public keys of the authority
        :param attribute: The attribute to revoke
        :param GPKs: A dict of user identifier to global public keys of the non-revoked users
        :return: The users key update key (KUK) and the ciphertext update key (CUK)
        """
        version_key = authority_secret['attr'][attribute]

        # It  generates  a  new  attribute  version  key
        new_version_key = self.group.random()
        while version_key == new_version_key:
            new_version_key = self.group.random()
        authority_secret['attr'][attribute] = new_version_key

        AUK = authority_secret['gamma'] * (new_version_key - version_key)
        KUK = {uid: GPKs[uid] ** (authority_secret['beta'] * AUK) for uid in GPKs.keys()}
        CUK = (authority_secret['beta'] / authority_secret['gamma']) * AUK

        authority_public['attr'][attribute] = authority_public['attr'][attribute] * (GPP['g'] ** AUK)

        return KUK, CUK

    def sk_update(self, USK, attribute, KUK):
        """Updates the user attribute secret key for the specified attribute (executed by non-revoked user)"""
        _, authority, _ = self.unpack_attribute(attribute)
        USK[authority]['AK'][attribute] = USK[authority]['AK'][attribute] * KUK

    def ct_update(self, GPP, CT, attribute, CUK):
        """
        Updates the cipher-text using the update key,
        because of the revoked attribute (executed by cloud provider)
        """
        CT['Ci'][attribute] = CT['Ci'][attribute] * (CT['D2'][attribute] ** CUK)

    def unpack_attribute(self, attribute):
        """
        Unpacks an attribute in attribute name, authority name and index
        :param attribute: The attribute to unpack
        :return: The attribute name, authority name and the attribute index, if present.

        >>> group = PairingGroup('SS512')
        >>> maabe = DACMACS(group)
        >>> maabe.unpack_attribute('STUDENT@UT')
        ('STUDENT', 'UT', None)
        >>> maabe.unpack_attribute('STUDENT@UT_2')
        ('STUDENT', 'UT', '2')
        """
        parts = re.split(r"[@_]", attribute)
        assert len(parts) > 1, "No @ char in [attribute@authority] name"
        return parts[0], parts[1], None if len(parts) < 3 else parts[2]


def test():
    # Central setup
    group = PairingGroup('SS512')
    dacmacs = DACMACS(group)
    GPP, GMK = dacmacs.setup()

    # Authorities setup
    authority1 = "A1"
    authority2 = "A2"
    authority1_attributes = ["ONE@A1", "TWO@A1"]
    authority2_attributes = ["THREE@A2", "FOUR@A2"]
    authority1_public, authority1_secret = dacmacs.authsetup(GPP, authority1_attributes)
    authority2_public, authority2_secret = dacmacs.authsetup(GPP, authority2_attributes)

    # Create user 'alice'
    alice_global_public, alice_global_secret = dacmacs.register_user(GPP)
    alice_secret1 = dacmacs.keygen(GPP, authority1_secret, authority1_public, ["ONE@A1", "TWO@A1"],
                                   alice_global_secret['cert'])
    alice_secret2 = dacmacs.keygen(GPP, authority2_secret, authority2_public, ["THREE@A2"],
                                   alice_global_secret['cert'])
    alice_secret_keys = {authority1: alice_secret1, authority2: alice_secret2}

    # Create user 'bob'
    bob_global_public, bob_global_secret = dacmacs.register_user(GPP)
    bob_secret1 = dacmacs.keygen(GPP, authority1_secret, authority1_public, ["ONE@A1", "TWO@A1"],
                                 bob_global_secret['cert'])
    bob_secret2 = dacmacs.keygen(GPP, authority2_secret, authority2_public, ["THREE@A2"],
                                 bob_global_secret['cert'])
    bob_secret_keys = {authority1: bob_secret1, authority2: bob_secret2}

    # Encrypt a message
    k = group.random(GT)
    policy_str = '((ONE@A1 or THREE@A2) and (TWO@A1 or FOUR@A2))'
    public_keys = {authority1: authority1_public, authority2: authority2_public}
    CT = dacmacs.encrypt(GPP, public_keys, k, policy_str)

    # Calculate tokens
    TK_alice = dacmacs.generate_token(GPP, CT, alice_global_public, alice_secret_keys)
    TK_bob = dacmacs.generate_token(GPP, CT, bob_global_public, bob_secret_keys)

    # Attempt to decrypt
    PT_alice = dacmacs.decrypt(CT, TK_alice, alice_global_secret)
    PT_bob = dacmacs.decrypt(CT, TK_bob, bob_global_secret)

    print("k")
    print(k)
    print("Decrypted")
    print(PT_alice)
    print(PT_bob)

    assert k == PT_alice
    assert k == PT_bob

    # Revoke "ONE@A1" from bob
    revoked_attribute = "ONE@A1"
    KUK, CUK = dacmacs.update_keygen(GPP, authority1_secret, authority1_public, revoked_attribute,
                                     {'alice': alice_global_public})
    # Send the key update key only to alice
    dacmacs.sk_update(alice_secret_keys, revoked_attribute, KUK['alice'])
    # Update the ciphertext
    dacmacs.ct_update(GPP, CT, revoked_attribute, CUK)

    # Calculate tokens
    TK_alice = dacmacs.generate_token(GPP, CT, alice_global_public, alice_secret_keys)
    TK_bob = dacmacs.generate_token(GPP, CT, bob_global_public, bob_secret_keys)

    # Attempt to decrypt
    PT_alice = dacmacs.decrypt(CT, TK_alice, alice_global_secret)
    PT_bob = dacmacs.decrypt(CT, TK_bob, bob_global_secret)

    print("k")
    print(k)
    print("Decrypted")
    print(PT_alice)
    print(PT_bob)

    assert k == PT_alice
    assert k != PT_bob


if __name__ == '__main__':
    test()
