"""
caslib.py
CAS Library for Python
Contact: esteve <esteve@iplantcollaborative.org>

Requirements:
  CAS 2.0+ Server
  httplib2

Basic Authentication Scenario:
  * Service wants to authenticate a user with CAS, once.

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
  * Service has 'authorized'/'protected' areas after initial login that require the user be CAS authorized
  * Users are authenticated for some time, to get more time they must be CAS authorized
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
                       to (IOU,ID) from PROXY_URL 
                      The SERVICE_URL should always redirect user to the correct locations depending on CAS validation.

    PROXY_CALLBACK_URL - This is a dummy URL, required by CAS server. 
    NOTE: <PROXY_CALLBACK_URL> Must be on same server AND RSA or VeriSign SSL Certified

    PROXY_URL - The request landing at this URL will have (ProxyID, ProxyIOU) in the query string (GET), from CAS server.
                    This page should record the ProxyID and ProxyIOU for immediate retrieval
  }

  * To programmatically determine user re-authorization: pass the last recorded proxyTicket for user to cas_proxyValidate(user, proxyTicket):
    
"""
import logging
import httplib2

#Global variables
AUTH_SERVER = SERVICE_URL = PROXY_URL = PROXY_CALLBACK_URL = ""
SELF_SIGNED_CERT = False

def cas_init(server_url, service_url, proxy_url='', proxy_callback=''):
  """
  (Optional) Provides a DEFAULT set of commands. 
  At any level these commands can be overridden by passing additional parameters

  server_url, service_url : Initializes caslib authentication service
  proxy_url and proxy_callback : Initialize optional proxy re-authentication service
  """
  global AUTH_SERVER , SERVICE_URL , PROXY_URL , PROXY_CALLBACK_URL
  AUTH_SERVER = server_url
  SERVICE_URL = service_url
  PROXY_URL = proxy_url if proxy_url is not None else ""
  PROXY_CALLBACK_URL = proxy_callback if proxy_callback is not None else ""

#Methods
def cas_serviceValidate(ticket, auth=AUTH_SERVER, service=SERVICE_URL, proxy=PROXY_URL):
    """
    Calls serviceValidate using (ticket)
    Call cas_init BEFORE making any cas calls!
    returns (truth, username [,proxyIOU] )
    """
    #global AUTH_SERVER , SERVICE_URL , PROXY_URL , PROXY_CALLBACK_URL

    #Invalid ticket (there is no ticket!)
    if ticket is None:
        if proxy != "":
            return (False,"","")
        return (False,"")

    #Use defaults if not set
    if service is None or service is '':
        logging.warn("CASLIB: service missing, use cas_init or set the 'service' parameter.")
    if auth is None or auth is '':
        logging.warn("CASLIB: Auth Server missing, use cas_init or set the 'auth' parameter.")

    cas_validate = auth + "/cas/serviceValidate?ticket=" + ticket + "&service=" + service
    if proxy != "":
        cas_validate += "&pgtUrl="+ proxy
    logging.info("CASLIB: /serviceValidate URL:"+cas_validate)
    username = ""
    try:
        h = httplib2.Http(disable_ssl_certificate_validation=SELF_SIGNED_CERT)#TODO:Remove on PROD
        header,response = h.request(cas_validate)
        username = parse_tag(response,"cas:user")
        logging.info("CASLIB: /serviceValidate User:"+username)
        if proxy != "":
            pgtIou = parse_tag(response,"cas:proxyGrantingTicket")
            logging.info("CASLIB: /serviceValidate PGTIOU:"+pgtIou)
            return (True,username,pgtIou)
        return (True,username)
    except Exception, e:
        logging.error("CASLIB: Exception at /serviceValidate:"+str(e))
    if proxy != "":
        return (False,username,"")
    return (False,username)

def cas_proxy(proxyTicket, auth=AUTH_SERVER, targetService=PROXY_CALLBACK_URL, proxy=PROXY_URL):
    """
    Calls CAS using proxy to see what user is logged in
    returns true if the user matches parameter 'user' 
    if empty, the targetService will be filled by PROXY_CALLBACK_URL
    """
    if proxyTicket is None or proxyTicket is '':
        logging.warn("CASLIB: proxyticket missing.")
        return ""

    if auth is None or auth is '':
        logging.warn("CASLIB: Auth Server missing, use cas_init or set the 'auth' parameter.")
    if targetService is None or targetService is '':
        logging.warn("CASLIB: targetService missing, use cas_init or set the 'targetService' parameter.")
    if proxy is None or proxy is '':
        logging.warn("CASLIB: proxy missing, use cas_init or set the 'proxy' parameter.")

    try:
        proxy = auth+"/cas/proxy?targetService="+targetService+"&pgt="+proxyTicket
        logging.info("CASLIB: /proxy URL:"+proxy)
        conn = httplib2.Http(disable_ssl_certificate_validation=SELF_SIGNED_CERT)
        (head,resp) = conn.request(proxy)
        casticket = parse_tag(resp,"cas:proxyTicket")
    except Exception, e:
        logging.error("CASLIB: Exception at /proxy:"+str(e))
        casticket = ""

    return casticket

def cas_proxyValidate(casticket, auth=AUTH_SERVER, service=PROXY_CALLBACK_URL):
    """
    Calls /cas/proxyValidate with 'casticket' from a previous call to /cas/proxy
    if empty, the service parameter will be filled by PROXY_CALLBACK_URL
    The CAS user will be returned
    """
    if service is None or service is '':
        logging.warn("CASLIB: service missing, use cas_init or set the 'service' parameter.")
    if auth is None or auth is '':
        logging.warn("CASLIB: Auth Server missing, use cas_init or set the 'auth' parameter.")

    try:
        cas_valid_url = auth+"/cas/proxyValidate?ticket="+casticket+"&service="+service
        logging.info("CASLIB: /proxyValidate URL:"+cas_valid_url)
        conn = httplib2.Http(disable_ssl_certificate_validation=SELF_SIGNED_CERT)
        (head,resp) = conn.request(cas_valid_url)
        casuser = parse_tag(resp,"cas:user")
    except Exception, e:
        logging.error("CASLIB: Exception at /proxyValidate:"+str(e))
        return "" 
    return casuser

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

    casticket = cas_proxy(proxyTicket)
    #A typical service will pass the 'casticket', then proxyValidate will return authorized user.
    return (user == cas_proxyValidate(casticket))

#Utiltiy Methods
def parse_tag(str,tag):
   """
     Common helper method used to extract values from the tags from str
   """
   tag1_pos1 = str.find("<" + tag)
   #  No tag found, return empty string.
   if tag1_pos1 == -1: return ""
   tag1_pos2 = str.find(">",tag1_pos1)
   if tag1_pos2 == -1: return ""
   tag2_pos1 = str.find("</" + tag,tag1_pos2)
   if tag2_pos1 == -1: return ""
   #Extract everything between the tags
   return str[tag1_pos2+1:tag2_pos1].strip()
