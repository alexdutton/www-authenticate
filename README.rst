WWW-Authenticate header parser
==============================

Parsing WWW-Authenticate headers is difficult. Let this tiny library do all the
hard work for you.

What's so difficult?
--------------------

The header contains a set of comma-separated challenges, but the parameters for
each challenge are also comma-separated. Some challenges in the wild don't have
parameters, which violates the spec. The ``Negotiate`` challenge eschews the
required name-value pairs and has a single string as its parameter.

Some servers may offer more challenges than you were expecting, but you'd still
like to notice the one you care about.

Usage
-----

It's really easy::

   import www_authenticate

   parsed = www_authenticate.parse(response.headers['WWW-Authenticate'])

   if 'Basic' in parsed:
       realm = parsed['Basic']['realm']
   if 'Negotiate' in parsed:
       challenge = parsed['Negotiate']

The returned object is a ``collections.OrderedDict`` with authentication scheme
names as keys. The values are either dictionaries, a single string, or ``None``
if there are no parameters.

Installation
------------

This package is in PyPI. Install with::

   $ pip install www-authenticate

There are no external dependencies.

