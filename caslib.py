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
                 cas_server_url+"/cas/login?service="+cas_service_url

    cas_service_url - The request landing at this URL will have a ticket, passed from CAS server.
                      This page should call 'serviceValidate' and record the user as authorized.
                      The cas_service_url should return the user to the correct locations depending on CAS validation.
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
                 cas_server_url+"/cas/login?service="+cas_service_url

    cas_service_url - The request landing at this URL will have a ticket in the query string (GET), passed from CAS server.
                      This page should call 'serviceValidate' 
                      This page should match:
                        (User,IOU) from serviceValidate
                       to (IOU,ID) from cas_proxy_url 
                      The cas_service_url should always redirect user to the correct locations depending on CAS validation.

    cas_proxy_callback - This is a dummy URL, required by CAS server. 
    NOTE: <cas_proxy_callback> Must be on same server AND RSA or VeriSign SSL Certified

    cas_proxy_url - The request landing at this URL will have (ProxyID, ProxyIOU) in the query string (GET), from CAS server.
                    This page should record the ProxyID and ProxyIOU for immediate retrieval
  }

  * To programmatically determine user re-authorization: pass the last recorded proxyTicket for user to cas_proxyValidate(user, proxyTicket):
    
"""
import logging
import httplib2

#Global variables
cas_server_url = cas_service_url = cas_proxy_url = cas_proxy_callback = ""
def cas_init(server_url, service_url, proxy_url='', proxy_callback=''):
  """
  server_url, service_url : Initializes caslib authentication service
  proxy_url and proxy_callback : Initialize optional proxy re-authentication service
  """
  global cas_server_url , cas_service_url , cas_proxy_url , cas_proxy_callback
  cas_server_url = server_url
  cas_service_url = service_url
  cas_proxy_url = proxy_url if proxy_url is not None else ""
  cas_proxy_callback = proxy_callback if proxy_callback is not None else ""

def cas_serviceValidate(ticket):
    """
    Calls serviceValidate using (ticket)
    Call cas_init BEFORE making any cas calls!
    returns (truth, username [,proxyIOU] )
    """
    global cas_server_url , cas_service_url , cas_proxy_url , cas_proxy_callback
    #Invalid ticket (there is no ticket!)
    if ticket is None:
        if cas_proxy_url != "":
            return (False,"","")
        return (False,"")
    if cas_proxy_url != "":
        cas_validate = cas_server_url + "/cas/serviceValidate?ticket=" + ticket + "&service=" + cas_service_url +"&pgtUrl="+cas_proxy_url
    else:
        cas_validate = cas_server_url + "/cas/serviceValidate?ticket=" + ticket + "&service=" + cas_service_url
    logging.info("cas_serviceValidate URL:"+cas_validate)
    username = ""
    try:
        h = httplib2.Http(disable_ssl_certificate_validation=True)#TODO:Remove on PROD
        header,response = h.request(cas_validate)
        username = parse_tag(response,"cas:user")
        logging.info("cas_serviceValidate User:"+username)
        if cas_proxy_url != "":
            pgtIou = parse_tag(response,"cas:proxyGrantingTicket")
            logging.info("cas_serviceValidate PGTIOU:"+pgtIou)
            return (True,username,pgtIou)
        return (True,username)
    except Exception, e:
        logging.error("cas_serviceValidate Exception:"+str(e))
    if cas_proxy_url != "":
        return (False,username,"")
    return (False,username)

def cas_proxy(proxyTicket, targetService=None):
    """
    Calls CAS using proxy to see what user is logged in
    returns true if the user matches parameter 'user' 
    if empty, the targetService will be filled by cas_proxy_callback
    """
    global cas_server_url , cas_service_url , cas_proxy_url , cas_proxy_callback
    if targetService is None:
        targetService = cas_proxy_callback
    try:
        cas_proxy_url = cas_server_url+"/cas/proxy?targetService="+targetService+"&pgt="+proxyTicket
        logging.info("cas_proxy /proxy URL:"+cas_proxy_url)
        conn = httplib2.Http()
        (head,resp) = conn.request(cas_proxy_url)
        casticket = parse_tag(resp,"cas:proxyTicket")
    except Exception, e:
        logging.error("cas_proxy Exception:"+str(e))
        casticket = ""
    return casticket

def cas_proxyValidate(user, casticket, service=None):
    """
    Calls /cas/proxyValidate with 'casticket' from a previous call to /cas/proxy
    returns true if the user matches parameter 'user' 
    if empty, OBthe service parameter will be filled by cas_proxy_callback
    """
    global cas_server_url , cas_service_url , cas_proxy_url , cas_proxy_callback
    if service is None:
        service = cas_proxy_callback
    try:
        cas_valid_url = cas_server_url+"/cas/proxyValidate?ticket="+casticket+"&service="+service
        logging.info("cas_proxyValidate /proxyValidate URL:"+cas_valid_url)
        conn = httplib2.Http()
        (head,resp) = conn.request(cas_valid_url)
        casuser = parse_tag(resp,"cas:user")
    except Exception, e:
        logging.error("cas_proxyValidate Exception:"+str(e))
        return False
    return (casuser == user)

def cas_reauthenticate(user, proxyTicket):
    """
    Generalizes the CAS proxy for simple reauthentication
    returns true if the user in the proxyTicket matches the 'user' 
    """
    casticket = cas_proxy(proxyTicket)
    return cas_proxyValidate(user, casticket)

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
   return str[tag1_pos2+1:tag2_pos1].strip()

