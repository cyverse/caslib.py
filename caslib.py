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
import httplib2

#Global variables
AUTH_SERVER = SERVICE_URL = PROXY_URL = PROXY_CALLBACK_URL = None
SELF_SIGNED_CERT = False

def cas_init(server_url, service_url, proxy_url=None, proxy_callback=None):
  """
  (Optional) Provides a DEFAULT set of commands. 
  At any level these commands can be overridden by passing additional parameters

  server_url, service_url : Initializes caslib authentication service
  proxy_url and proxy_callback : Initialize optional proxy re-authentication service
  """
  global AUTH_SERVER , SERVICE_URL , PROXY_URL , PROXY_CALLBACK_URL
  AUTH_SERVER = server_url
  SERVICE_URL = service_url
  PROXY_URL = proxy_url 
  PROXY_CALLBACK_URL = proxy_callback 

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
    logging.info("CASLIB: /proxy URL:"+proxy)
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
    logging.info("CASLIB: /proxyValidate URL:"+cas_valid_url)
    return cas_callHTTP(cas_valid_url)

def cas_reauthenticate(user, proxyTicket):
    """
    Generalizes the CAS proxy for simple reauthentication
    returns true if the user in the proxyTicket matches the parameter 'user' 
    """
    if user is None or user is "":
        logging.warn("CASLIB: User missing")
        return False
    if proxyTicket is None or proxyTicket is "":
        logging.warn("CASLIB: proxyTicket missing")
        return False

    proxy_response = cas_proxy(proxyTicket)
    casticket = proxy_response.map[proxy_response.type].get('proxyTicket','')
    logging.info("CAS Ticket:"+casticket)

    pv_response = cas_proxyValidate(casticket)
    proxyUser = pv_response.map[pv_response.type].get('user','')
    logging.info("CAS ProxyUser:"+proxyUser)

    return ((user == proxyUser),pv_response)

#Utiltiy Methods

def cas_callHTTP(url):
    try:
        conn = httplib2.Http(disable_ssl_certificate_validation=SELF_SIGNED_CERT)
        (head,resp) = conn.request(url)
        return CASResponse(resp)
    except Exception, e:
        logging.error("CASLIB: Exception at /proxyValidate:"+str(e))
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

  logging.info(response)
  logging.info('-->')
  logging.info(xmlDict)
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
                print "text",nodeDict
        elif child.nodeType == child.ELEMENT_NODE:
            children = xml2dict(child)
            nodeDict[tagName] = dict(nodeDict.get(tagName,{}).items() + children.items())
    return nodeDict

class CASResponse:
  def __init__(self, response=None):
    (self.xml, self.type, self.map) = parseCASResponse(response)
    self.success = "success" in self.type.lower()
