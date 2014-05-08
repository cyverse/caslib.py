"""
caslib.py
CAS Library for Python
Contact: esteve <esteve@iplantcollaborative.org>

Requirements:
  CAS 2.0+ Server
  httplib2

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

    def cas_callHTTP(self, url):
        try:
            response = requests.get(url, verify=self.self_signed_cert)
            return CASResponse(response.text)
        except Exception, e:
            logging.exception("CASLIB: Error retrieving a response")
            raise#return None

    def _service_validate_url(self, ticket):
        return "%s/cas/serviceValidate?ticket=%s&service=%s%s"\
               % (self.server_url, ticket, self.service_url, 
               "" if not self.proxy_url else "&pgtUrl=%s" % self.proxy_url)
    def _proxy_url(self, ticket):
        return "%s/cas/proxy?targetService=%s&pgt=%s"\
               % (self.server_url, self.proxy_callback, ticket)
    def _proxy_validate_url(self, ticket):
        return "%s/cas/proxyValidate?ticket=%s&service=%s"\
               % (self.server_url, ticket, self.service_url)
    #cas_validate = auth + "/cas/serviceValidate?ticket=" + ticket + "&service=" + service + "&pgtUrl="+ proxy
    #proxy = auth+"/cas/proxy?targetService="+targetService+"&pgt="+proxyTicket
    #cas_valid_url = auth+"/cas/proxyValidate?ticket="+casticket+"&service="+service
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
        return self.cas_callHTTP(cas_validate_url)

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
        return self.cas_callHTTP(proxy_url)

    def cas_proxyValidate(proxied_serviceticket, auth=None, service=None):
        """
        Calls /cas/proxyValidate with the service ticket obtained from a call to cas_proxy
        The CAS user will be returned
        """
        if not self.proxy_url:
            raise Exception(
                    "Conflict: Client is not initialized with a proxy URL")
        cas_valid_url = self._proxy_validate_url(proxied_serviceticket)
        return self.cas_callHTTP(cas_valid_url)
    
    def cas_reauthenticate(self, user, proxyTicket):
        """
        Generalizes the CAS proxy for simple reauthentication
        returns true if the user in the proxyTicket matches the parameter 'user' 
        """
        if not user:
            logging.warn("CASLIB: User missing, cannot reauthenticate.")
            return (False, None)
        if not proxyTicket:
            logging.warn("CASLIB: proxyTicket missing, cannot reauthenticate.")
            return (False, None)
        proxy_response = self.cas_proxy(proxyTicket)
        proxy_obj = proxy_response.map[proxy_response.type]
        if isinstance(proxy_obj,dict):
            casticket = proxy_obj.get('proxyTicket','')
        else:
            logging.error("Proxy Object DOES NOT MATCH. "
                         "This will require a manual check "
                         "that response.type(%s) matches the key in "
                         "response.map(%s)"
                         % (proxy_response.type, proxy_response.map))
            casticket = ''
        if not casticket:
            logging.error("Proxy Object MISSING TICKET! "
                          "This will require a manual check "
                          "that proxy_obj(%s) contains 'proxyTicket'"
                          % proxy_obj)
            return (False, proxy_response)
        #Validate the ticket -- Is it authentic?
        pv_response = self.cas_proxyValidate(casticket)
        validate_obj = pv_response.map[pv_response.type]
    
        #Authentic tickets will provide the username the ticket belongs to
        if isinstance(validate_obj,dict):
            proxyUser = validate_obj.get('user','')
        else:
            logging.error("ProxyValidate Object DOES NOT MATCH. "
                         "This will require a manual check "
                         "that response.type(%s) matches the key in "
                         "response.map(%s)"
                         % (pv_response.type, pv_response.map))
        if not proxyUser:
            logging.error("ProxyValidate Object MISSING USER! "
                          "This will require a manual check "
                          "that proxy_obj(%s) contains 'user'"
                          % proxy_obj)
            return (False, pv_response)
    
        logging.info("CAS Ticket:%s CAS ProxyUser:%s User Tested: %s"
                     % (casticket, proxyUser, user))
        return ((user == proxyUser),pv_response)
### All below this line will be deprecated//Old version..
import httplib2


#Global variables
AUTH_SERVER = SERVICE_URL = PROXY_URL = PROXY_CALLBACK_URL = None
SELF_SIGNED_CERT = False

def cas_init(server_url, service_url, proxy_url=None, proxy_callback=None,
             self_signed_cert=False):
  """
  (Optional) Provides a DEFAULT set of commands. 
  At any level these commands can be overridden by passing additional parameters

  server_url, service_url : Initializes caslib authentication service
  proxy_url and proxy_callback : Initialize optional proxy re-authentication service
  """
  global AUTH_SERVER , SERVICE_URL , PROXY_URL , PROXY_CALLBACK_URL ,\
         SELF_SIGNED_CERT
  AUTH_SERVER = server_url
  SERVICE_URL = service_url
  PROXY_URL = proxy_url 
  PROXY_CALLBACK_URL = proxy_callback 
  SELF_SIGNED_CERT = self_signed_cert

def cas_setServiceURL(service_url):
  global SERVICE_URL
  SERVICE_URL= service_url 

#Methods
def cas_serviceValidate(ticket, auth=None, service=None, proxy=None):
    """
    Calls serviceValidate using (ticket)
    Call cas_init BEFORE making any cas calls!
    returns cas_response
    """
    #SET THE CONSTANTS
    if auth is None:
        auth=AUTH_SERVER
    if service is None:
        service=SERVICE_URL
    if proxy is None:
        proxy=PROXY_URL

    #Invalid ticket (there is no ticket!)
    if ticket is None:
        if proxy is not None:
            return (False,"","")
        return (False,"")

    #Use defaults if not set
    if service is None or service is '':
        logging.warn("CASLIB: service missing, use cas_init or set the 'service' parameter.")
    if auth is None or auth is '':
        logging.warn("CASLIB: Auth Server missing, use cas_init or set the 'server' parameter.")

    cas_validate = auth + "/cas/serviceValidate?ticket=" + ticket + "&service=" + service
    if proxy is not None:
        cas_validate += "&pgtUrl="+ proxy
    logging.info("CASLIB: /serviceValidate URL:"+cas_validate)
    return cas_callHTTP(cas_validate)

def cas_proxy(proxyTicket, auth=None, targetService=None, proxy=None):
    """
    Calls CAS using proxy to see what user is logged in
    returns true if the user matches parameter 'user' 
    if empty, the targetService will be filled by PROXY_CALLBACK_URL
    """
    #global AUTH_SERVER , SERVICE_URL , PROXY_URL , PROXY_CALLBACK_URL
    if auth is None:
        auth=AUTH_SERVER
    if targetService is None:
        targetService=PROXY_CALLBACK_URL
    if proxy is None:
        proxy=PROXY_URL

    if proxyTicket is None or proxyTicket is '':
        logging.warn("CASLIB: proxyticket missing.")
        return ""

    if auth is None or auth is '':
        logging.warn("CASLIB: Auth Server missing, use cas_init or set the 'auth' parameter.")
    if targetService is None or targetService is '':
        logging.warn("CASLIB: targetService missing, use cas_init or set the 'targetService' parameter.")
    if proxy is None or proxy is '':
        logging.warn("CASLIB: proxy missing, use cas_init or set the 'proxy' parameter.")
    
    proxy = auth+"/cas/proxy?targetService="+targetService+"&pgt="+proxyTicket
    return cas_callHTTP(proxy)

def cas_proxyValidate(casticket, auth=None, service=None):
    """
    Calls /cas/proxyValidate with 'casticket' from a previous call to /cas/proxy
    if empty, the service parameter will be filled by PROXY_CALLBACK_URL
    The CAS user will be returned
    """
    #global AUTH_SERVER , SERVICE_URL , PROXY_URL , PROXY_CALLBACK_URL
    if auth is None:
        auth=AUTH_SERVER
    if service is None:
        service=PROXY_CALLBACK_URL

    if service is None or service is '':
        logging.warn("CASLIB: service missing, use cas_init or set the 'service' parameter.")
    if auth is None or auth is '':
        logging.warn("CASLIB: Auth Server missing, use cas_init or set the 'auth' parameter.")

    cas_valid_url = auth+"/cas/proxyValidate?ticket="+casticket+"&service="+service
    return cas_callHTTP(cas_valid_url)

def cas_reauthenticate(user, proxyTicket):
    """
    Generalizes the CAS proxy for simple reauthentication
    returns true if the user in the proxyTicket matches the parameter 'user' 
    """
    if user is None or user is "":
        logging.warn("CASLIB: User missing, cannot reauthenticate.")
        return (False, None)
    if proxyTicket is None or proxyTicket is "":
        logging.warn("CASLIB: proxyTicket missing, cannot reauthenticate.")
        return (False, None)

    proxy_response = cas_proxy(proxyTicket)
    proxy_obj = proxy_response.map[proxy_response.type]
    if isinstance(proxy_obj,dict):
      
        casticket = proxy_obj.get('proxyTicket','')
    else:
        logging.error("Proxy Object DOES NOT MATCH. "
                     "This will require a manual check "
                     "that response.type(%s) matches the key in "
                     "response.map(%s)"
                     % (proxy_response.type, proxy_response.map))
        casticket = ''
    if not casticket:
        logging.error("Proxy Object MISSING TICKET! "
                      "This will require a manual check "
                      "that proxy_obj(%s) contains 'proxyTicket'"
                      % proxy_obj)
        return (False, proxy_response)
    #Validate the ticket -- Is it authentic?
    pv_response = cas_proxyValidate(casticket)
    validate_obj = pv_response.map[pv_response.type]

    #Authentic tickets will provide the username the ticket belongs to
    if isinstance(validate_obj,dict):
        proxyUser = validate_obj.get('user','')
    else:
        logging.error("ProxyValidate Object DOES NOT MATCH. "
                     "This will require a manual check "
                     "that response.type(%s) matches the key in "
                     "response.map(%s)"
                     % (pv_response.type, pv_response.map))
    if not proxyUser:
        logging.error("ProxyValidate Object MISSING USER! "
                      "This will require a manual check "
                      "that proxy_obj(%s) contains 'user'"
                      % proxy_obj)
        return (False, pv_response)

    logging.info("CAS Ticket:%s CAS ProxyUser:%s User Tested: %s"
                 % (casticket, proxyUser, user))
    return ((user == proxyUser),pv_response)

#Utiltiy Methods

def cas_callHTTP(url):
    try:
        conn = httplib2.Http(disable_ssl_certificate_validation=SELF_SIGNED_CERT)
        (head,resp) = conn.request(url)
        return CASResponse(resp)
    except Exception, e:
        logging.exception("CASLIB: Error retrieving a response")
        return None

def parseCASResponse(response):
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
    xmlDict = xml2dict(casNode)
  except Exception, e:
    logging.warn(str(e))

  return (response, casType, xmlDict)

def xml2dict(tag):
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
                logging.info("text",nodeDict)
        elif child.nodeType == child.ELEMENT_NODE:
            children = xml2dict(child)
            nodeDict[tagName] = dict(nodeDict.get(tagName,{}).items() + children.items())
    return nodeDict

class CASResponse:
  def __init__(self, response=None):
    (self.xml, self.type, self.map) = parseCASResponse(response)
    self.success = "success" in self.type.lower()
    self.object = self.map[self.type]
