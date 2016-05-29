from __future__ import unicode_literals, print_function, division
import requests

url = 'http://aws.amazon.com/cn/'
requests.get(url, headers={'Accept-Encoding': 'deflate'}, timeout=3)