"""
caslib.py
CAS Library for Python
Contact: esteve <esteve@iplantcollaborative.org>

Requirements:
  CAS 2.0+ Server

Basic Authentication Scenario:
  * Service only wants to authenticate once to check a user has validated with CAS 

Basic Usage:
  * Web server acting as CAS Client needs two URLs:
  {
    login - This url is a landing page for the user. When they click login they should be redirected to :
                 AUTH_SERVER+"/cas/login?service="+SERVICE_URL

    SERVICE_URL - The request landing at this URL will have a ticket, passed from CAS server.
                      This page should call 'serviceValidate' and record the user as authorized.
                      The SERVICE_URL should return the user to the correct locations depending on CAS validation.
  }

Advanced Authentication Scenario:
  * Service wants to authenticate a user with CAS

    AND

  * After some time, service wants to ensure the same user is CAS authorized
  * Service has 'authorized'/'protected' areas after initial login that require the user be CAS authenticated
  * Users are authenticated for some time, to get more time they must be CAS authenticated
  * Any other reason that a service must test user authenticity more than once

Advanced Usage:
  *** A Database (Or other method) to store and lookup (User,IOU & IOU,ID) will be required ***

  *Web server acting as CAS Client needs four URLs:
  {
    login - This url is a landing page for the user. When they click [login] they should be redirected to :
                 AUTH_SERVER+"/cas/login?service="+SERVICE_URL

    SERVICE_URL - The request landing at this URL will have a ticket in the query string (GET), passed from CAS server.
                      This page should call 'serviceValidate' 
                      This page should match:
                         (User,IOU) from serviceValidate
                      to (IOU, ID ) from PROXY_URL 
                      The SERVICE_URL should always redirect user to the correct locations depending on CAS validation.

    PROXY_CALLBACK_URL - This is a dummy URL, required by CAS server. 
    NOTE: <PROXY_CALLBACK_URL> Must be on same server AND RSA or VeriSign SSL Certified

    PROXY_URL - The request landing at this URL will have (ProxyID, ProxyIOU) in the query string (GET), from CAS server.
                    This page should record the ProxyID and ProxyIOU for immediate retrieval
  }

  * To programmatically determine user re-authorization: pass the last recorded proxyTicket for user to cas_proxyValidate(user, proxyTicket):
    
"""
from xml.dom.minidom import parse, parseString
import logging
import requests

class CASClient():
    """
    Creates a new 'connection' to the CAS server
    keeping track of information about the current service request and/or proxy
    information.
    """
    def __init__(self, server_url, service_url,
                 proxy_url=None, proxy_callback=None, self_signed_cert=False):
        # Gather Parameters
        self.server_url = server_url
        self.service_url = service_url
        self.proxy_url = proxy_url
        self.proxy_callback = proxy_callback
        self.self_signed_cert = self_signed_cert

    def get_cas_response(self, url):
        try:
            response = requests.get(url, verify=self.self_signed_cert)
            return CASResponse(response.text)
        except Exception, e:
            logging.exception("CASLIB: Error retrieving a response")
            return None


    def _service_validate_url(self, ticket):
        return "%s/cas/serviceValidate?ticket=%s&service=%s%s"\
               % (self.server_url, ticket, self.service_url, 
               "" if not self.proxy_url else "&pgtUrl=%s" % self.proxy_url)
    def _proxy_url(self, ticket):
        return "%s/cas/proxy?targetService=%s&pgt=%s"\
               % (self.server_url, self.proxy_callback, ticket)
    def _proxy_validate_url(self, ticket):
        return "%s/cas/proxyValidate?ticket=%s&service=%s"\
               % (self.server_url, ticket, self.proxy_callback)
    def _logout_url(self, service_url):
        return self.cas_server + "/cas/logout?service=" + service_url

    def _login_url(self, gateway=False):
        url =  self.cas_server + "/cas/login?service=" + self.validator_url
        if (gateway):
            url += '&gateway=true'
        return url

    #Methods
    def cas_serviceValidate(self, ticket):
        """
        Calls serviceValidate using (ticket)
        returns (validTicket, username, proxied_user)
        """
        if ticket is None:
            if self.proxy_url:
                return (False,"","")
            return (False,"")
    
        #Use defaults if not set
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
                    "Conflict: Client is not initialized with a proxy callback URL")
        proxy_url = self._proxy_url(proxy_ticket)
        return self.get_cas_response(proxy_url)

    def cas_proxyValidate(self, proxied_serviceticket):
        """
        Calls /cas/proxyValidate with the service ticket obtained from a call to cas_proxy
        The CAS user will be returned
        """
        if not self.proxy_url:
            raise Exception(
                    "Conflict: Client is not initialized with a proxy URL")
        cas_valid_url = self._proxy_validate_url(proxied_serviceticket)
        return self.get_cas_response(cas_valid_url)
    
    #Composite methods
    def reauthenticate(self, proxyGrantingTicket, username=None):
        """
        Generalizes the CAS proxy for simple reauthentication
        PARAMS:
        * proxyGrantingTicket - A ticket we can use to reauthenticate, if it is valid.
        * username - If the PGT is valid and its ticket produces a user, that
                     user must match the username to be a validTicket
        RETURNS:
        (validTicket, response)
        """
        if not proxyGrantingTicket:
            logging.warn("CASLIB: proxyGrantingTicket missing, cannot reauthenticate.")
            return (False, None)
        proxy_response = self.cas_proxy(proxyGrantingTicket)
        if not proxy_response.object:
            raise Exception("Proxy Object DOES NOT MATCH."
                         " This will require a manual check"
                         " that response.type(%s) is an EXACT key match"
                         " to the key found in response.map:%s"
                         % (proxy_response.type, proxy_response.map))
        elif isinstance(proxy_response.object, str):
            logger.error("ERROR on /proxy: Server returned:%s" % (proxy_response.object,))
            return (False, proxy_response)
        if not proxy_response.proxy_ticket:
            logging.error("Proxy Object MISSING TICKET! "
                          "This will require a manual check "
                          "that the response object (%s) contains 'proxyTicket'"
                          % proxy_response.object)
            return (False, proxy_response)
        #Validate the ticket -- Is it authentic?
        validate_response = self.cas_proxyValidate(proxy_response.proxy_ticket)
    
        #Authentic tickets will provide the username the ticket belongs to
        if not validate_response.object:
            raise Exception("ProxyValidate Object DOES NOT MATCH."
                         " This will require a manual check"
                         " that response.type(%s) is an EXACT key match"
                         " to the key found in response.map:%s"
                         % (validate_response.type, validate_response.map))
        elif isinstance(validate_response.object,str):
            raise Exception("ERROR on /proxyValidate: Server returned:%s"
            % (validate_response.object,))
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
        (self.xml, self.type, self.map) = self.parse_cas_response(response)
        self.success = "success" in self.type.lower()
        self.object = self.map.get(self.type)
        if not isinstance(self.object, dict):
            return
        #NOTE: Not all of these attributes will exist for a given type.
        # The values you need are supecific to the type of request being made.
        # For more information, RTD
        self.user = self.object.get('user')
        self.attributes = self.object.get('attributes')
        #If using proxy:
        self.proxy_granting_ticket = self.object.get('proxyGrantingTicket')
        self.proxy_ticket = self.object.get('proxyTicket')

    def parse_cas_response(self, response):
        casNode = None
        casType = "NoResponse"
        xmlDict = {}
        if response is None or len(response) == 0:
            return (response, casType, xmlDict)
        try:
            doc = parseString(response)
            nodeEl = doc.documentElement
            if nodeEl.nodeName != 'cas:serviceResponse':
                raise Exception("Parsing CAS Response failed. Expected cas:serviceResponse as head element in XML response.")
            #First level, find out what type of CAS call it is
            for child in nodeEl.childNodes:
                if child.nodeType == child.ELEMENT_NODE:
                    casNode = child
                    casType = child.nodeName.replace("cas:","")
            #Grab relevant info from remaining XML
            xmlDict = self.xml2dict(casNode)
        except Exception, e:
          logging.warn(str(e))
      
        return (response, casType, xmlDict)
  
    def xml2dict(self, tag):
        """
        Recursively create python dict's to replace the nested XML structure
        """
        nodeDict = {}
        tagName = tag.nodeName.replace("cas:","")
        for child in tag.childNodes:
            if child.nodeType == child.TEXT_NODE:
                text = child.nodeValue
                if len(text.strip()) > 0:
                    nodeDict = {tagName : text.strip()}
            elif child.nodeType == child.ELEMENT_NODE:
                children = self.xml2dict(child)
                nodeDict[tagName] = dict(nodeDict.get(tagName,{}).items() + children.items())
        return nodeDict
  
