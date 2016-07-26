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

        Attribute revocation
        # >>> group = PairingGroup('SS512')
        # >>> dacmacs = DACMACS(group)
        # >>> GPP, GMK = dacmacs.setup()
        # >>> users = {}  # public user data
        # >>> authorities = {}
        # >>> authorityAttributes = ["ONE", "TWO", "THREE", "FOUR"]
        # >>> authority1 = "authority1"
        # >>> authority_public1, authority_secret1  = dacmacs.authsetup(GPP, authorityAttributes)
        # >>> alice = dict({'id': 'alice', 'authoritySecretKeys': {}, 'keys': None})
        # >>> alice_public, alice_secret = dacmacs.register_user(GPP)
        # >>> bob = dict({'id': 'bob', 'authoritySecretKeys': {}, 'keys': None})
        # >>> bob_public, bob_secret = dacmacs.register_user(GPP)
        # >>> for attr in authorityAttributes[0:-1]:
        # ...     _ = dacmacs.keygen(GPP, authorities[authority1], attr, alice_public, alice_secret)
        # ...     _ = dacmacs.keygen(GPP, authorities[authority1], attr, alice_public, alice_secret)
        # >>> k = group.random(GT)
        # >>> policy_str = '((ONE or THREE) and (TWO or FOUR))'
        # >>> CT = dacmacs.encrypt(GPP, policy_str, k, authorities[authority1])
        # >>> TK1a = dacmacs.generate_token(GPP, CT, alice['authoritySecretKeys'], alice['keys'][0])
        # >>> PT1a = dacmacs.decrypt(CT, TK1a, alice['keys'][1])
        # >>> TK1b = dacmacs.generate_token(GPP, CT, bob['authoritySecretKeys'], bob['keys'][0])
        # >>> PT1b = dacmacs.decrypt(CT, TK1b, bob['keys'][1])
        # >>> k == PT1a
        # True
        # >>> k == PT1b
        # True
        #
        # revoke bob on "ONE"
        # >>> attribute = "ONE"
        # >>> UK = dacmacs.ukeygen(GPP, authorities[authority1], attribute, users[alice['id']])
        # >>> dacmacs.skupdate(alice['authoritySecretKeys'], attribute, UK['KUK'])
        # >>> dacmacs.ctupdate(GPP, CT, attribute, UK['CUK'])
        # >>> TK2a = dacmacs.generate_token(GPP, CT, alice['authoritySecretKeys'], alice['keys'][0])
        # >>> PT2a = dacmacs.decrypt(CT, TK2a, alice['keys'][1])
        # >>> TK2b = dacmacs.generate_token(GPP, CT, bob['authoritySecretKeys'], bob['keys'][0])
        # >>> PT2b = dacmacs.decrypt(CT, TK2b, bob['keys'][1])
        # >>> k == PT2a
        # True
        # >>> k != PT2b
        # True
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

        C = reduce(lambda x, y: x * y['e(g,g)^alpha'], pks.values(), m) ** secret
        C1 = GPP['g'] ** secret
        # I dont know if this is correct: the paper states this incorrect
        C2 = reduce(lambda x, y: x * y['g^(1/beta)'], pks.values(), self.group.init(1, GT)) ** secret
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
            dividend = pair(CT['C1'], SK[authority_name]['K']) * ~pair(SK[authority_name]['R'], CT['C2'])
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

    def ukeygen(self, GPP, authority, attribute, userObj):
        """Generate update keys for users and cloud provider (executed by attribute authority?)"""
        ASK, _, authAttrs = authority
        oldVersionKey = authAttrs[attribute]['VK']
        newVersionKey = oldVersionKey
        while oldVersionKey == newVersionKey:
            newVersionKey = self.group.random()
        authAttrs[attribute]['VK'] = newVersionKey

        u = userObj['u']

        AUK = ASK['gamma'] * (newVersionKey - oldVersionKey)
        KUK = GPP['g'] ** (u * ASK['beta'] * AUK)
        CUK = ASK['beta'] * AUK / ASK['gamma']

        authAttrs[attribute]['PK'] = authAttrs[attribute]['PK'] * (GPP['g'] ** AUK)

        return {'KUK': KUK, 'CUK': CUK}

    def skupdate(self, USK, attribute, KUK):
        """Updates the user attribute secret key for the specified attribute (executed by non-revoked user)"""
        USK['AK'][attribute] = USK['AK'][attribute] * KUK

    def ctupdate(self, GPP, CT, attribute, CUK):
        """
        Updates the cipher-text using the update key,
        because of the revoked attribute (executed by cloud provider)
        """
        CT['C'][attribute] = CT['C'][attribute] * (CT['DS'][attribute] ** CUK)

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


def basicTest():
    group = PairingGroup('SS512')
    dacmacs = DACMACS(group)
    GPP, GMK = dacmacs.setup()
    authority1 = "A1"
    authority2 = "A2"
    authority1_attributes = ["ONE@A1", "TWO@A1"]
    authority2_attributes = ["THREE@A2", "FOUR@A2"]
    authority1_public, authority1_secret = dacmacs.authsetup(GPP, authority1_attributes)
    authority2_public, authority2_secret = dacmacs.authsetup(GPP, authority2_attributes)
    alice_global_public, alice_global_secret = dacmacs.register_user(GPP)
    alice_secret1 = dacmacs.keygen(GPP, authority1_secret, authority1_public, ["ONE@A1", "TWO@A1"],
                                   alice_global_secret['cert'])
    alice_secret2 = dacmacs.keygen(GPP, authority2_secret, authority2_public, ["THREE@A2"],
                                   alice_global_secret['cert'])
    k = group.random(GT)
    print("k")
    print(k)
    policy_str = '((ONE@A1 or THREE@A2) and (TWO@A1 or FOUR@A2))'
    public_keys = {authority1: authority1_public, authority2: authority2_public}
    print("Public keys")
    print(public_keys)
    CT = dacmacs.encrypt(GPP, public_keys, k, policy_str)
    secret_keys = {authority1: alice_secret1, authority2: alice_secret2}
    print("Secret keys")
    print(secret_keys)
    TK = dacmacs.generate_token(GPP, CT, alice_global_public, secret_keys)
    PT = dacmacs.decrypt(CT, TK, alice_global_secret)
    print("Decrypted")
    print(PT)


def revokedTest():
    print("RUN revokedTest")
    groupObj = PairingGroup('SS512')
    dac = DACMACS(groupObj)
    GPP, GMK = dac.setup()

    users = {}  # public user data
    authorities = {}

    authorityAttributes = ["ONE", "TWO", "THREE", "FOUR"]
    authority1 = "authority1"

    dac.authsetup(GPP, authority1, authorityAttributes, authorities)

    alice = {'id': 'alice', 'authoritySecretKeys': {}, 'keys': None}
    alice['keys'], users[alice['id']] = dac.register_user(GPP)

    bob = {'id': 'bob', 'authoritySecretKeys': {}, 'keys': None}
    bob['keys'], users[bob['id']] = dac.register_user(GPP)

    for attr in authorityAttributes[0:-1]:
        dac.keygen(GPP, authorities[authority1], attr, users[alice['id']], alice['authoritySecretKeys'])
        dac.keygen(GPP, authorities[authority1], attr, users[bob['id']], bob['authoritySecretKeys'])

    k = groupObj.random(GT)

    policy_str = '((ONE or THREE) and (TWO or FOUR))'

    CT = dac.encrypt(GPP, policy_str, k, authorities[authority1])

    TK1a = dac.generate_token(GPP, CT, alice['authoritySecretKeys'], alice['keys'][0])
    PT1a = dac.decrypt(CT, TK1a, alice['keys'][1])
    TK1b = dac.generate_token(GPP, CT, bob['authoritySecretKeys'], bob['keys'][0])
    PT1b = dac.decrypt(CT, TK1b, bob['keys'][1])

    assert k == PT1a, 'FAILED DECRYPTION (1a)!'
    assert k == PT1b, 'FAILED DECRYPTION (1b)!'
    print('SUCCESSFUL DECRYPTION 1')

    # revoke bob on "ONE"
    attribute = "ONE"
    UK = dac.ukeygen(GPP, authorities[authority1], attribute, users[alice['id']])
    dac.skupdate(alice['authoritySecretKeys'], attribute, UK['KUK'])
    dac.ctupdate(GPP, CT, attribute, UK['CUK'])

    TK2a = dac.generate_token(GPP, CT, alice['authoritySecretKeys'], alice['keys'][0])
    PT2a = dac.decrypt(CT, TK2a, alice['keys'][1])
    TK2b = dac.generate_token(GPP, CT, bob['authoritySecretKeys'], bob['keys'][0])
    PT2b = dac.decrypt(CT, TK2b, bob['keys'][1])

    assert k == PT2a, 'FAILED DECRYPTION (2a)!'
    assert k != PT2b, 'SUCCESSFUL DECRYPTION (2b)!'
    print('SUCCESSFUL DECRYPTION 2')


def test():
    groupObj = PairingGroup('SS512')
    # k = groupObj.random()
    # print "k", k, ~k, k * ~k
    # g = groupObj.random(G1)
    # print "g", g, pair(g, g)
    # gt = groupObj.random(GT)
    # print "gt", gt


if __name__ == '__main__':
    basicTest()
    # test()
