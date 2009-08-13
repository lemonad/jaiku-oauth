#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
The MIT License

Copyright (c) 2009 Jonas Nockert

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


A library for authorizing and accessing Jaiku via OAuth.

Requires:
  OAuth: http://code.google.com/p/oauth/
  pycurl: http://pycurl.sourceforge.net/ (only if using proxy)


"""

import pprint
import datetime
import simplejson
import string
import oauth.oauth as oauth
try:
    # Httplib does not support using proxy over https so use
    # pycurl if available
    import pycurl, StringIO
    use_pycurl = True
except ImportError:
    import httplib, socket
    use_pycurl = False

try:
    from local_settings import *
except ImportError:
    http_debug_flag = False
    consumer_key = ''
    consumer_secret = ''
    access_token_key = ''
    access_token_secret = ''
    username = ''
    include_replies = None


__author__ = 'Jonas Nockert'
__license__ = "MIT"
__version__ = '0.1.0'
__email__ = "jonasnockert@gmail.com"

JAIKU_REQUEST_TOKEN_URL = 'http://localhost:8080/api/request_token'
JAIKU_ACCESS_TOKEN_URL = 'http://localhost:8080/api/access_token'
JAIKU_AUTHORIZATION_URL = 'http://localhost:8080/api/authorize'
JAIKU_API_BASE_URL = 'http://localhost:8080/api/json'
JAIKU_URL = 'http://localhost:8080'
JAIKU_TIMEOUT = 30

class JaikuError(RuntimeError):

    def __init__(self, message='Jaiku API error occured.'):
        self.message = message

class JaikuOAuthClient(oauth.OAuthClient):

    def __init__(self, consumer_key, consumer_secret,
                  proxy_host=None, proxy_port=None,
                  proxy_username=None, proxy_password=None):
        """
        Register applications at http://www.jaiku.com/api/keys
        in order to get consumer keys and secrets.

        Keyword arguments:

        consumer key -- identifies a Jaiku application
        consumer secret -- establishes ownership of the consumer key
        proxy host -- host name of proxy server (optional)
        proxy port -- port number (integer, optional)
        proxy username -- used if proxy requires authentication (optional)
        proxy password -- used if proxy requires authentication (optional)

        """
        if use_pycurl:
            self._connection = pycurl.Curl()
            self._connection.setopt(pycurl.CONNECTTIMEOUT, JAIKU_TIMEOUT)
            self._connection.setopt(pycurl.TIMEOUT, JAIKU_TIMEOUT)
            if http_debug_flag:
                self._connection.setopt(pycurl.VERBOSE, 1)
        else:
            self._connection = httplib.HTTPConnection("%s" % JAIKU_URL)
            if http_debug_flag:
                self._connection.set_debuglevel(100000)

        if proxy_host is not None or proxy_port is not None:
            if not use_pycurl:
                raise JaikuError("Use of proxy settings requires pycurl "
                                  "to be installed.")
            elif proxy_host is None or proxy_port is None:
                raise JaikuError("Proxy settings missing host and/or port.")
            elif ((proxy_username is not None and proxy_password is None) or
                 (proxy_username is None and proxy_password is not None)):
                raise JaikuError("Proxy settings missing username or "
                                  "password.")
            try:
                self._connection.setopt(pycurl.PROXY, proxy_host)
                self._connection.setopt(pycurl.PROXYPORT, proxy_port)
                if proxy_username is not None:
                    self._connection.setopt(pycurl.PROXYUSERPWD, "%s:%s" % (
                                            proxy_username, proxy_password))
            except:
                raise JaikuError("Could not set up proxied connection.")

        try:
            self._consumer = oauth.OAuthConsumer(consumer_key, consumer_secret)
            # Jaiku does not support PLAINTEXT, only HMAC-SHA1
            self._signature = oauth.OAuthSignatureMethod_HMAC_SHA1()
        except oauth.OAuthError, m:
            raise JaikuError(m.message)

    def close(self):
        """Explicitly closes HTTP connection."""

        # both pycurl and httplib use the same close method
        self._connection.close()

    def fetch_request_token(self):
        """
        Retrieve an unauthorized request token that, in the next step of the
        OAuth process, will be used to authorize an application.

        """
        try:
            oauth_request = oauth.OAuthRequest.from_consumer_and_token(
                                            self._consumer,
                                            http_method='GET',
                                            http_url=JAIKU_REQUEST_TOKEN_URL)
            oauth_request.sign_request(self._signature, self._consumer, None)
            headers = oauth_request.to_header()
        except oauth.OAuthError, m:
            raise JaikuError(m.message)

        if use_pycurl:
            # convert header dictionary to pycurl header list
            header_list = []
            for h in headers:
                header_list.append("%s:%s" % (h, headers[h]))

            try:
                content = StringIO.StringIO()
                self._connection.setopt(pycurl.HTTPHEADER, header_list)
                self._connection.setopt(pycurl.WRITEFUNCTION, content.write)
                self._connection.setopt(pycurl.URL, JAIKU_REQUEST_TOKEN_URL)
                self._connection.perform()
            except pycurl.error, (n, m):
                raise JaikuError(m)

            status = self._connection.getinfo(pycurl.HTTP_CODE)
            if status == 401:
                raise JaikuError("Consumer key and/or secret not accepted.")
            elif status != 200:
                raise JaikuError("Request to '%s' returned HTTP code %d." % (
                                  JAIKU_REQUEST_TOKEN_URL, status))
            r = content.getvalue()
        else:
            try:
                self._connection.request(oauth_request.http_method,
                                          JAIKU_REQUEST_TOKEN_URL,
                                          headers=headers)
            except socket.gaierror, (n, m):
                raise JaikuError(m)

            response = self._connection.getresponse()
            if response.status == 401:
                raise JaikuError("Consumer key and/or secret not accepted.")
            elif response.status != 200:
                raise JaikuError("Request to '%s' returned HTTP code %d." % (
                                  JAIKU_REQUEST_TOKEN_URL, response.status))
            r = response.read()

        try:
            token = oauth.OAuthToken.from_string(r)
        except oauth.OAuthError, m:
            raise JaikuError(m.message)
        return token

    def get_authorization_url(self, token):
        """
        Return URL from which a user can authorize Jaiku API access for
        a given application.

        Keyword arguments:

        token  -- an unauthorized OAuth request token

        """
        try:
            oauth_request = oauth.OAuthRequest.from_token_and_callback(
                token=token,
                http_url=JAIKU_AUTHORIZATION_URL)
            url = oauth_request.to_url()
        except oauth.OAuthError, m:
            raise JaikuError(m.message)
        return url

    def fetch_access_token(self, unauth_request_token, oauth_verifier):
        """
        After the user has authorizated API access via the authorization URL,
        get the (semi-)permanent access key using the user-authorized request
        token.

        Observe that the extra step (oauth_verifier) per OAuth 1.0 Revision A
        is not yet implemented in Jaiku

        Keyword arguments:

        unauth_request_token -- The user-authorized OAuth request token
        oauth_verifier -- Per OAuth 1.0 Revision A

        """

        url = JAIKU_ACCESS_TOKEN_URL

        try:
            oauth_request = oauth.OAuthRequest.from_consumer_and_token(
                self._consumer,
                token=unauth_request_token,
                http_method='GET',
                http_url=url,
                verifier=oauth_verifier)
            oauth_request.sign_request(self._signature,
                                       self._consumer,
                                       unauth_request_token)
            headers = oauth_request.to_header()
        except oauth.OAuthError, m:
            raise JaikuError(m.message)

        if use_pycurl:
            # convert header dictionary to pycurl header list
            header_list = []
            for h in headers:
                header_list.append("%s:%s" % (h, headers[h]))

            try:
                content = StringIO.StringIO()
                self._connection.setopt(pycurl.HTTPHEADER, header_list)
                self._connection.setopt(pycurl.WRITEFUNCTION, content.write)
                self._connection.setopt(pycurl.URL, url)
                self._connection.perform()
            except pycurl.error, (n, m):
                raise JaikuError(m)

            status = self._connection.getinfo(pycurl.HTTP_CODE)
            if status == 401:
                raise JaikuError("Request token not authorized.")
            elif status != 200:
                raise JaikuError("Request to '%s' returned HTTP code %d." % (
                                  url, status))
            r = content.getvalue()
            if http_debug_flag:
                print "----response----"
                print r
                print "----end-response----"
        else:
            try:
                self._connection.request(oauth_request.http_method,
                                         url,
                                         headers=headers)
            except socket.gaierror, (n, m):
                raise JaikuError(m)

            response = self._connection.getresponse()
            r = response.read()
            if http_debug_flag:
                print "----response----"
                print r
                print "----end-response----"
            if response.status == 401:
                raise JaikuError("Request token not authorized.")
            elif response.status != 200:
                raise JaikuError("Resource '%s' returned HTTP code %d." % (
                                  url, response.status))

        try:
            access_token = oauth.OAuthToken.from_string(r)
        except oauth.OAuthError, m:
            raise JaikuError(m.message)
        return access_token

    def fetch_resource(self, token, url, parameters=None):
        """
        Retrieve a Jaiku API resource.

        Keyword arguments:

        token -- an OAuth access token
        url -- a Jaiku API URL (excluding query parameters)
        parameters -- Used to pass query parameters to add to the
                      request (optional).

        """
        try:
            oauth_request = oauth.OAuthRequest.from_consumer_and_token(
                                                self._consumer,
                                                token=token,
                                                http_method='GET',
                                                http_url=url,
                                                parameters=parameters)
            oauth_request.sign_request(self._signature, self._consumer, token)
            url = oauth_request.to_url()
        except oauth.OAuthError, m:
            raise JaikuError(m.message)

        if use_pycurl:
            try:
                content = StringIO.StringIO()
                self._connection.setopt(pycurl.WRITEFUNCTION, content.write)
                self._connection.setopt(pycurl.URL, url)
                self._connection.perform()
            except pycurl.error, (n, m):
                raise JaikuError(m)

            status = self._connection.getinfo(pycurl.HTTP_CODE)
            if status != 200:
                raise JaikuError("Resource '%s' returned HTTP code %d." % (
                                  url, status))
            return content.getvalue()
        else:
            try:
                self._connection.request(oauth_request.http_method, url)
            except socket.gaierror, (n, m):
                raise JaikuError(m)

            response = self._connection.getresponse()
            if response.status != 200:
                raise JaikuError("Resource '%s' returned HTTP code %d." % (
                                  url, response.status))
            return response.read()

def get_actor_overview(consumer_key, consumer_secret,
                    access_token, access_token_secret,
                    username,
                    limit=10,
                    offset=None,
                    proxy_host=None, proxy_port=None,
                    proxy_username=None, proxy_password=None):
    """
    Fetch a user's Jaiku posts and returns a json decoded python structure.

    Keyword arguments:

    consumer key -- identifies a Jaiku application
    consumer secret -- establishes ownership of the consumer key
    access token -- an OAuth access token which enables access to protected
                    resources on behalf of the user
    access token secret -- establish ownership of the access token
    username -- a Jaiku username for whom to fetch posts
    limit -- how many entries to fetch, max 100 (optional)
    offset -- a string representing a datetime before which to retrieve
              entries (optional).
              See http://code.google.com/p/jaikuengine/source/browse/trunk/doc/request_timestamp.txt
              for a list of accepted formats.
    proxy host -- host name of proxy server (optional)
    proxy port -- port number (integer, optional)
    proxy username -- used if proxy requires authentication (optional)
    proxy password -- used if proxy requires authentication (optional)

    """
    #if not offset:
    #    now = datetime.datetime.utcnow()
    #    offset = now.strftime("%Y-%m-%d %H:%M:%S")

    #parameters = {'method': 'entry_get_actor_overview',
    #              'nick': username}
    url = JAIKU_API_BASE_URL
    url = 'http://lemonad.jaiku.com/overview/json'
    url = 'http://localhost:8080/user/lemonad/overview/json'

    client = JaikuOAuthClient(consumer_key, consumer_secret,
                                proxy_host=proxy_host,
                                proxy_port=proxy_port,
                                proxy_username=proxy_username,
                                proxy_password=proxy_password)
    token = oauth.OAuthToken(access_token, access_token_secret)
    json = client.fetch_resource(token, url)
    client.close()
    
    try:
        pyjson = simplejson.loads(json)
    except ValueError:
        raise JaikuError("Could not decode json.")

    return pyjson


#
# If invoked directly, go through Jaiku API authorization process,
# step by step.
#

if __name__ == "__main__":
    proxy_yesno = raw_input("Use http proxy? [y/N]: ")
    if string.strip((proxy_yesno.lower())[0:1]) == 'y':
        proxy_host = raw_input("Proxy hostname: ")
        proxy_port = int(raw_input("Proxy port: "))
        proxy_username = raw_input("Proxy username (return for none): ")
        if len(proxy_username) != 0:
            proxy_password = raw_input("Proxy password: ")
        else:
            proxy_username = None
            proxy_password = None
    else:
        proxy_host = None
        proxy_port = None
        proxy_username = None
        proxy_password = None

    if consumer_key == '' or consumer_secret == '':
        print "\n#1 ... visit " \
            "http://www.jaiku.com/api/keys\n" \
            "       to register your application.\n"

        consumer_key = raw_input("Enter consumer key: ")
        consumer_secret = raw_input("Enter consumer secret: ")

    if consumer_key == '' or consumer_secret == '':
        print "*** Error: Consumer key or (%s) secret (%s) not valid.\n" % (
                                                consumer_key, consumer_secret)
        quit()

    if(access_token_key == '' or access_token_secret == ''):
        try:
            client = JaikuOAuthClient(consumer_key, consumer_secret,
                                proxy_host=proxy_host,
                                proxy_port=proxy_port,
                                proxy_username=proxy_username,
                                proxy_password=proxy_password)
        except JaikuError, m:
            print "*** Error: %s" % m.message
            quit()

        print "\n#2 ... Fetching request token.\n"

        try:
            unauth_request_token = client.fetch_request_token()
        except JaikuError, m:
            print "*** Error: %s" % m.message
            quit()
        unauth_request_token_key = unauth_request_token.key
        unauth_request_token_secret = unauth_request_token.secret

        try:
            url = client.get_authorization_url(unauth_request_token)
        except JaikuError, m:
            print "*** Error: %s" % m.message
            quit()

        print "#3 ... Manually authorize via url: %s\n" % url

        oauth_verifier = raw_input("After authorizing, enter the OAuth" \
                                   " verifier (four characters): ")

        print "\n#4 ... Fetching access token.\n"

        unauth_request_token = oauth.OAuthToken(unauth_request_token_key,
                              unauth_request_token_secret)
        try:
            access_token = client.fetch_access_token(unauth_request_token,
                                                     oauth_verifier)
        except JaikuError, m:
            print "*** Error: %s" % m.message
            quit()
        access_token_key = access_token.key
        access_token_secret = access_token.secret

        print "Your access token: "
        print "\nKey:    %s" % access_token_key
        print "Secret: %s" % access_token_secret

    if username == '':
        username = raw_input("Enter Jaiku username (or return for current): ")

    print "\n#5 ... Fetching latest user post.\n"

    try:
        p = get_actor_overview(consumer_key,
                          consumer_secret,
                          access_token_key,
                          access_token_secret,
                          username,
                          proxy_host=proxy_host,
                          proxy_port=proxy_port,
                          proxy_username=proxy_username,
                          proxy_password=proxy_password)
        print "Result:\n"
        print p
    except JaikuError, m:
        print "*** Error: %s" % m.message
        quit()
