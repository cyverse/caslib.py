"""
caslib.py
CAS Library for Python
Contact: Steve Gregory <sgregory@iplantcollaborative.org>

Requirements:
  CAS 3.5.x - 4.0.0+ Server

Basic Authentication Scenario:
  * Service only wants to authenticate once to check
    a user has validated with CAS

Basic Usage:
  * Web server acting as CAS Client needs two URLs:
  {
    login - This url is a landing page for the user.
            When they click login they should be redirected to :
                AUTH_SERVER+"/cas/login?service="+SERVICE_URL

    SERVICE_URL - The request landing at this URL will have a ticket,
                  passed from CAS server.
                  This page should call 'serviceValidate' and
                  record the user as authorized.
                  The SERVICE_URL should return the user
                  to the correct locations depending on CAS validation.
  }

Advanced Authentication Scenario:
  * Service wants to authenticate a user with CAS

    AND

  * After some time, service wants to ensure the same user is CAS authorized
  * Service has 'authorized'/'protected' areas after initial login
    that require the user be CAS authenticated
  * Users are authenticated for some time, to get more time
    they must be CAS authenticated
  * Any other reason that a service must test user authenticity more than once

Advanced Usage:
  *** A Database is required to store & lookup (User,IOU & IOU,ID)***

  *Web server acting as CAS Client needs four URLs:
  {
    login - This url is a landing page for the user.
            When they click [login] they should be redirected to :
                 AUTH_SERVER+"/cas/login?service="+SERVICE_URL

    SERVICE_URL - The request landing at this URL will have a ticket
                      in the query string (GET), passed from CAS server.
                      This page should call 'serviceValidate'
                      This page should match:
                         (User,IOU) from serviceValidate
                      to (IOU, ID ) from PROXY_URL
                      The SERVICE_URL should always redirect user to
                      the correct locations depending on CAS validation.

    PROXY_CALLBACK_URL - This is a dummy URL, required by CAS server.
    NOTE: <PROXY_CALLBACK_URL> Must be on same server AND
          RSA or VeriSign SSL Certified

    PROXY_URL - The request landing at this URL will have (ProxyID, ProxyIOU)
    in the query string (GET), from CAS server.
    This page should record the ProxyID and ProxyIOU for immediate retrieval
  }

  * To programmatically determine user re-authorization: pass the last recorded
    proxyTicket for user to cas_proxyValidate(user, proxyTicket):

"""
from xml.dom.minidom import parseString
from datetime import datetime, timedelta
import json
import logging
import requests
import uuid
try:
    import urlparse
except ImportError:
    from urllib import parse as urlparse
############################################################################


class CASClient():
    """
    Creates a new 'connection' to the CAS server
    keeping track of information about the current service request and/or proxy
    information.
    """
    def __init__(self, server_url, service_url,
                 proxy_url=None, proxy_callback=None,
                 auth_prefix='/cas', self_signed_cert=False):
        # Gather Parameters
        self.server_url = server_url
        self.service_url = service_url
        self.proxy_url = proxy_url
        self.proxy_callback = proxy_callback
        self.auth_prefix = auth_prefix
        self.self_signed_cert = self_signed_cert

    def get_cas_response(self, url):
        try:
            response = requests.get(url, verify=self.self_signed_cert)
            return CASResponse(response.text)
        except Exception:
            logging.exception("CASLIB: Error retrieving a response")
            return None

    def _service_validate_url(self, ticket):
        return "%s%s/serviceValidate?ticket=%s&service=%s%s"\
               % (self.server_url, self.auth_prefix, ticket, self.service_url,
                  "" if not self.proxy_url else "&pgtUrl=%s" % self.proxy_url)

    def _proxy_url(self, ticket):
        return "%s%s/proxy?targetService=%s&pgt=%s"\
               % (self.server_url, self.auth_prefix,
                  self.proxy_callback, ticket)

    def _proxy_validate_url(self, ticket):
        return "%s%s/proxyValidate?ticket=%s&service=%s"\
               % (self.server_url, self.auth_prefix,
                  ticket, self.proxy_callback)

    def _logout_url(self, service_url):
        return "%s%s/logout?service=%s"\
                % (self.server_url, self.auth_prefix, service_url)

    def _login_url(self, gateway=False):
        url = "%s%s/login?service=%s"\
                % (self.server_url, self.auth_prefix, self.service_url)
        if (gateway):
            url += '&gateway=true'
        return url

    # Methods
    def cas_serviceValidate(self, ticket):
        """
        Calls serviceValidate using (ticket)
        returns (validTicket, username, proxied_user)
        """
        if ticket is None:
            if self.proxy_url:
                return (False, "", "")
            return (False, "")

        # Use defaults if not set
        cas_validate_url = self._service_validate_url(ticket)
        logging.info("CASLIB: /serviceValidate URL:"+cas_validate_url)
        return self.get_cas_response(cas_validate_url)

    def cas_proxy(self, proxy_ticket):
        """
        Calls CAS using proxy to see what user is logged in
        returns true if the user matches parameter 'user'
        if empty, the targetService will be filled by PROXY_CALLBACK_URL
        """
        if not self.proxy_callback:
            raise Exception(
                    "Conflict: Client is not initialized "
                    "with a proxy callback URL")
        proxy_url = self._proxy_url(proxy_ticket)
        return self.get_cas_response(proxy_url)

    def cas_proxyValidate(self, proxied_serviceticket):
        """
        Calls /cas/proxyValidate with the service ticket
        obtained from a call to cas_proxy
        The CAS user will be returned
        """
        if not self.proxy_url:
            raise Exception(
                    "Conflict: Client is not initialized with a proxy URL")
        cas_valid_url = self._proxy_validate_url(proxied_serviceticket)
        return self.get_cas_response(cas_valid_url)

    # Composite methods
    def reauthenticate(self, proxyGrantingTicket, username=None):
        """
        Generalizes the CAS proxy for simple reauthentication
        PARAMS:
        * proxyGrantingTicket - A ticket we can use to reauthenticate,
                                if it is valid.
        * username - If the PGT is valid and its ticket produces a user, that
                     user must match the username to be a validTicket
        RETURNS:
        (validTicket, response)
        """
        if not proxyGrantingTicket:
            logging.warn("CASLIB: proxyGrantingTicket missing, "
                         "cannot reauthenticate.")
            return (False, None)
        proxy_response = self.cas_proxy(proxyGrantingTicket)
        if proxy_response.error_str:
            logging.error("ERROR on /proxy: Server returned:%s"
                          % (proxy_response.object,))
            return (False, proxy_response)
        elif not proxy_response.object:
            raise Exception("Proxy Object DOES NOT MATCH."
                            " This will require a manual check"
                            " that response.type(%s) is an EXACT key match"
                            " to the key found in response.map:%s"
                            % (proxy_response.type, proxy_response.map))
        if not proxy_response.proxy_ticket:
            logging.error("Proxy Object MISSING TICKET! "
                          "This will require a manual check "
                          "that the response object (%s) "
                          "contains 'proxyTicket'"
                          % proxy_response.object)
            return (False, proxy_response)
        # Validate the ticket -- Is it authentic?
        validate_response = self.cas_proxyValidate(proxy_response.proxy_ticket)

        # Authentic tickets will provide the username the ticket belongs to
        if validate_response.error_str:
            raise Exception("ERROR on /proxyValidate: Server returned:%s"
                            % (validate_response.object,))
        elif not validate_response.object:
            raise Exception("ProxyValidate Object DOES NOT MATCH."
                            " This will require a manual check"
                            " that response.type(%s) is an EXACT key match"
                            " to the key found in response.map:%s"
                            % (validate_response.type, validate_response.map))
        elif not validate_response.user:
            logging.error("Object is missing 'user' attribute."
                          "Update the CAS client with the associated value"
                          "found in this object: %s"
                          % (validate_response.object))
            return (False, validate_response)

        logging.info("CAS Ticket:%s CAS ProxyUser:%s User Tested: %s"
                     % (validate_response.proxy_ticket,
                        validate_response.user,
                        username))
        # If we are Testing against a username, it must match.
        # Otherwise the valid ticket is sufficient
        return ((username == validate_response.user) if username else True,
                validate_response)


class CASResponse:
    def __init__(self, response):
        self.response = response
        (self.xml, self.type, self.map) = self.parse_response(response)
        self.success = "success" in self.type.lower()
        resp_object = self.map.get(self.type)
        if isinstance(resp_object, dict):
            self.object = resp_object
            self.error_str = None
        else:
            self.object = {}
            self.error_str = resp_object
        # NOTE: Not all of these attributes will exist for a given type.
        # The values you need are supecific to the type of request being made.
        # For more information, RTD
        self.user = self.object.get('user')
        self.attributes = self.object.get('attributes')
        # If using proxy:
        self.proxy_granting_ticket = self.object.get('proxyGrantingTicket')
        self.proxy_ticket = self.object.get('proxyTicket')

    def parse_response(self, response):
        casNode = None
        casType = "NoResponse"
        xmlDict = {}
        if response is None or len(response) == 0:
            return (response, casType, xmlDict)
        try:
            doc = parseString(response)
            nodeEl = doc.documentElement
            if nodeEl.nodeName != 'cas:serviceResponse':
                raise Exception(
                    "Parsing CAS Response failed. "
                    "Expected cas:serviceResponse as "
                    "head element in XML response.")
            # First level, find out what type of CAS call it is
            for child in nodeEl.childNodes:
                if child.nodeType == child.ELEMENT_NODE:
                    casNode = child
                    casType = child.nodeName.replace("cas:", "")
            # Grab relevant info from remaining XML
            xmlDict = self.xml2dict(casNode)
        except Exception as e:
            logging.warn(str(e))

        return (response, casType, xmlDict)

    def xml2dict(self, tag):
        """
        Recursively create python dict's to replace the nested XML structure
        """
        nodeDict = {}
        tagName = tag.nodeName.replace("cas:", "")
        for child in tag.childNodes:
            if child.nodeType == child.TEXT_NODE:
                text = child.nodeValue
                if len(text.strip()) > 0:
                    nodeDict = {tagName: text.strip()}
            elif child.nodeType == child.ELEMENT_NODE:
                children = self.xml2dict(child)
                nodeDict.setdefault(tagName, {}).update(children)
        return nodeDict


class SAMLClient():
    """
    Creates a new 'connection' to the CAS server
    keeping track of information about the current service request and/or proxy
    information.
    """
    def __init__(self, server_url, service_url,
                 auth_prefix='/cas', envelope_txt=None):
        # Gather Parameters
        self.server_url = server_url
        self.service_url = service_url
        self.auth_prefix = auth_prefix

    def _service_validate_envelope(self, ticket):
        return """<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header/>
  <SOAP-ENV:Body>
    <samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1"
      MinorVersion="1" RequestID="_192.168.16.51.1024506224022"
      IssueInstant="2002-06-19T17:03:44.022Z">
      <samlp:AssertionArtifact>
        %s
      </samlp:AssertionArtifact>
    </samlp:Request>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>""" % (ticket,)

    def get_saml_response(self, url, envelope):
        try:
            response = requests.post(url, data=envelope)
            return SAMLResponse(response.text)
        except Exception:
            logging.exception("SAML: Error retrieving a response")
            raise

    def _service_validate_url(self, ticket):
        return "%s%s/samlValidate?TARGET=%s&service=%s&ticket=%s"\
               % (self.server_url, self.auth_prefix, self.service_url,
                  self.service_url, ticket)

    def _logout_url(self, service_url):
        return self.server_url + "%s/logout?service=%s"\
                % (self.auth_prefix, service_url)

    def _login_url(self, gateway=False):
        url = self.server_url + "%s/login?service=%s"\
                % (self.auth_prefix, self.service_url)
        if (gateway):
            url += '&gateway=true'
        return url

    def _login_request(self, username, password):
        url = self._login_url()
        if username and password:
            login_ticket = "LT-CASLIB-%s" % uuid.uuid4()
            url += '&username=%s' % username
            url += '&password=%s' % password
            url += '&lt=%s' % login_ticket
        return self.get_saml_response(url)

    # Methods
    def saml_serviceValidate(self, ticket):
        """
        Calls serviceValidate using (ticket)
        returns (validTicket, username, proxied_user)
        """
        if ticket is None:
            if self.proxy_url:
                return (False, "", "")
            return (False, "")

        # Use defaults if not set
        saml_validate_url = self._service_validate_url(ticket)
        saml_envelope = self._service_validate_envelope(ticket)
        logging.info("samlLIB: /serviceValidate URL:"+saml_validate_url)
        return self.get_saml_response(saml_validate_url, saml_envelope)


class SAMLResponse:
    def __init__(self, response):
        self.response = response
        (self.xml, self.map) = self.parse_response(response)
        self.success = "success" in self.map.get('Status', {})\
                                            .get('Value', '').lower()
        if not self.success:
            self.user = None
            self.attributes = None
            return
        # NOTE: Not all of these attributes will exist for a given type.
        # The values you need are supecific to the type of request being made.
        # For more information, RTD
        self.user = self._get_user()
        self.attributes = self._get_attributes()

    def __str__(self):
        return "caslib.SAMLResponse - Success: %s, User: %s"\
                % (self.success, self.user)

    def __unicode__(self):
        return "caslib.SAMLResponse - Success: %s, User: %s"\
                % (self.success, self.user)

    def _get_attributes(self):
        return self.map['Assertion']['AttributeStatement']

    def _get_user(self):
        return self.map['Assertion']['AttributeStatement']\
                       ['Subject']['NameIdentifier']

    def parse_response(self, response):
        samlMap = {}
        if response is None or len(response) == 0:
            return (None, samlMap)
        try:
            doc = parseString(response)
            nodeEl = doc.documentElement
            # Peel back the envelope until we get to the response..
            while nodeEl.nodeName != 'saml1p:Response':
                if not nodeEl.childNodes:
                    break
                nodeEl = nodeEl.childNodes[0]
            if nodeEl.nodeName != 'saml1p:Response':
                raise Exception(
                    "Parsing saml Response failed. "
                    "Expected saml1p:Response as in XML response.")
            # First level, SAML should contain an Assertion and a Status
            for child in nodeEl.childNodes:
                if child.nodeType != child.ELEMENT_NODE:
                    raise Exception(
                        "Parsing saml Response failed. "
                        "Expected ELEMENT_NODE to follow saml1p:Response.")
                # Grab relevant info from remaining XML
                samlMap.update(self.xml2dict(child))
        except Exception as e:
            logging.warn(str(e))
            raise Exception("Malformed SAML response: %s" % response)

        return (doc, samlMap)

    def clean_tag_name(self, tag):
        real_name = tag.nodeName
        return real_name\
            .replace("saml1:", "")\
            .replace("saml1p:", "")\
            .replace("SOAP-ENV", "")

    def parse_attr(self, tag):
        attr_key = tag.getAttribute('AttributeName')
        attr_values = tag.getElementsByTagName("saml1:AttributeValue")
        py_values = [node.childNodes[0].data for node in attr_values]
        return {attr_key: py_values}

    def xml2dict(self, tag):
        """
        Recursively create python dict's to replace the nested XML structure
        """
        # Attributes must be parsed separately, since the namespaces conflict.
        if tag.nodeName == 'saml1:Attribute':
            return self.parse_attr(tag)

        # These attributes are the key-value pairs associated on the same XML
        # line.
        if tag.hasAttributes():
            nodeMap = dict(
                    (key, value) for (key, value) in
                    tag.attributes.items())
        else:
            nodeMap = {}
        tagName = self.clean_tag_name(tag)
        # Any XML nested inside will be caught with this loop(Will recurse)
        children_map = {}
        for child in tag.childNodes:
            if child.nodeType == child.TEXT_NODE:
                text = child.nodeValue
                nodeMap[tagName] = text.strip()
                return nodeMap
            elif child.nodeType != child.ELEMENT_NODE:
                raise Exception("Parsing saml Response failed. "
                                "Expected TEXT_NODE|ELEMENT_NODE to follow %s"
                                % tag.nodeName)
            children_map.update(self.xml2dict(child))
        nodeMap[tagName] = children_map

        return nodeMap


class OAuthClient():
    """
    This is a 'CAS' OAuthClient, and although it implements OAuth 2.0 Protocol,
    it is NOT feature-complete, and in some cases works differently than
    'other' OAuth2 servers
    """
    def __init__(self, server_url, callback_url, client_id, client_secret,
                 auth_prefix='/cas', envelope_txt=None):
        # Gather Parameters
        self.server_url = server_url
        self.callback_url = callback_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_prefix = auth_prefix

    def get_access_token(self, oauth_code):
        oauth_resp = self._validateCode(oauth_code)
        if not oauth_resp or not oauth_resp.token or not oauth_resp.expires:
            return None, None
        expiry_date = datetime.now() + timedelta(seconds=oauth_resp.expires)
        return oauth_resp.token, expiry_date

    def get_profile(self, access_token):
        """
        Using the access_token, retrieve Profile
        """
        if access_token is None:
            return None

        # Use defaults if not set
        oauth_profile_url = self._profile_url(access_token)
        oauth_resp = self.get_oauth_response(oauth_profile_url, "json")
        if 'error' in oauth_resp.map:
            raise Exception("Error occurred during call to %s - %s" % (oauth_profile_url, oauth_resp.map))
        return oauth_resp.profile

    def logout(self, redirect):
        return self._logout_url(redirect)

    def authorize_url(self):
        return self._login_url()

    def get_oauth_response(self, url, mime_type='urlencoded'):
        try:
            response = requests.get(url)
            return OAuthResponse(response.text, mime_type)
        except Exception:
            logging.exception("CASLIB: Error retrieving an OAuth response")
            raise

    def _profile_url(self, access_token):
        return "%s%s/oauth2.0/profile?"\
                "access_token=%s"\
                % (self.server_url, self.auth_prefix, access_token)

    def _access_token_url(self, code):
        return "%s%s/oauth2.0/accessToken?" \
                "code=%s&client_id=%s&client_secret=%s&redirect_uri=%s&" \
                "grant_type=authorization_code" \
                % (self.server_url, self.auth_prefix,
                   code, self.client_id, self.client_secret, self.callback_url)

    def _logout_url(self, service_url):
        return self.server_url + "%s/logout?service=%s"\
               % (self.auth_prefix, service_url)

    def _login_url(self):
        url = "%s%s/oauth2.0/authorize?client_id=%s&response_type=code&redirect_uri=%s" %\
              (self.server_url, self.auth_prefix,
               self.client_id, self.callback_url)
        return url

    def _validateCode(self, code):
        """
        Calls accessToken using (code) and other req. params
        returns (validTicket, username)
        """
        if code is None:
            return (False, "")
        # Use defaults if not set
        oauth_validate_url = self._access_token_url(code)
        oauth_resp = self.get_oauth_response(oauth_validate_url, "urlencoded")
        return oauth_resp


class OAuthResponse:
    def __init__(self, response, mime_type='urlencoded'):
        self.response = response
        # Raw mapping
        self.map = self.parse_response(response, mime_type)
        # Convenience
        self.token = None
        self.expires = -1
        self.profile = {}

        if "access_token" in self.map:
            self.token = self.map['access_token'][0]

        for key in ["expires", "expires_in"]:
            if key in self.map:
                self.expires = int(self.map.get(key)[0])
                break

        if "id" in self.map:
            self._build_profile()

    def _build_profile(self):
        self.profile['username'] = self.map["id"]
        attributes = self.map['attributes']
        if isinstance(attributes, list): # CAS 4
            for attr in attributes:
                if isinstance(attr, dict):
                    for k, v in attr.items():
                        self.profile[k] = v
        elif isinstance(attributes, dict): # CAS 5
            self.profile.update(attributes)

    def parse_response(self, response, mime_type):
        response_map = {}
        if 'urlencoded' in mime_type:
            # NOTE: The map for a urlencoded value will always
            # return values as a LIST, due to the inherit ambiguity
            # of 'urlencoded' variables.
            response_map = urlparse.parse_qs(response)
        elif 'json' in mime_type:
            try:
                response_map = json.loads(response)
            except ValueError:
                logging.error(
                    "CAS FAILURE: Expected a JSON object. Received %s"
                    % response)
        else:
            logging.error("Expected mime_type <%s> to be in range: "
                          "[urlencoded, json]" % mime_type)
        return response_map
