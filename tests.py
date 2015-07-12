import itertools
import unittest

import www_authenticate

values = [
    'Negotiate, Bearer realm="example.com", Basic realm="example.com"',
    'Bearer realm="example.com", Negotiate, Basic realm="example.com"',
    'Negotiate, Bearer realm="example.com"',
    'Negotiate',
    'Bearer realm="example.com"',
    'Negotiate abcdef',
    'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"',
    'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", Negotiate',
    'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", Bearer realm="example.com"',
]

challenges = (
    ('Negotiate',
     ('negotiate', None)),
    ('Negotiate abcdef',
     ('negotiate', 'abcdef')),
    ('Bearer realm=example.com',
     ('bearer', {'realm': 'example.com'})),
    ('Bearer realm="example.com"',
     ('bearer', {'realm': 'example.com'})),
    ('Digest realm="example.com", qop="auth,auth-int", nonce="abcdef", opaque="ghijkl"',
     ('digest', {'realm': 'example.com', 'qop': 'auth,auth-int', 'nonce': 'abcdef', 'opaque': 'ghijkl'})),
)


class ParseTestCase(unittest.TestCase):
    def testValid(self):
        for r in range(1, len(challenges) + 1):
            for permutation in itertools.permutations(challenges, r):
                # Skip those that have the same authentication scheme more than once.
                if len(set(challenge[1][0] for challenge in permutation)) != len(permutation):
                    continue
                full_challenge = ', '.join(challenge[0] for challenge in permutation)
                print(full_challenge)
                parsed = www_authenticate.parse(full_challenge)
                for left, right in zip(permutation, parsed):
                    self.assertEqual(left[1][0], right)
                    self.assertEqual(left[1][1], parsed[right])

