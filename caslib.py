"""
caslib.py
CAS Library for Python
Contact:     Steven Gregory <esteve@iplantcollaborative.org>
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

def cas_reauthByProxy(user, proxyTicket):
    """
    Calls CAS using proxy to see what user is logged in
    returns true if the user matches parameter 'user' 
    """
    global cas_server_url , cas_service_url , cas_proxy_url , cas_proxy_callback
    try:
        cas_proxy_url = cas_server_url+"/cas/proxy?targetService="+cas_proxy_callback+"&pgt="+proxyTicket
        logging.info("cas_reauthByProxy /proxy URL:"+cas_proxy_url)
        conn = httplib2.Http()
        (head,resp) = conn.request(cas_proxy_url)
        casticket = parse_tag(resp,"cas:proxyTicket")
        cas_valid_url = cas_server_url+"/cas/proxyValidate?ticket="+casticket+"&service="+cas_proxy_callback
        logging.info("cas_reauthByProxy /proxyValidate URL:"+cas_valid_url)
        (head,resp) = conn.request(cas_valid_url)
        casuser = parse_tag(resp,"cas:user")
    except Exception, e:
        logging.error("cas_reauthByProxy Exception:"+str(e))
        return False

    return (casuser == user)

def parse_tag(str,tag):
   tag1_pos1 = str.find("<" + tag)
   #  No tag found, return empty string.
   if tag1_pos1 == -1: return ""
   tag1_pos2 = str.find(">",tag1_pos1)
   if tag1_pos2 == -1: return ""
   tag2_pos1 = str.find("</" + tag,tag1_pos2)
   if tag2_pos1 == -1: return ""
   return str[tag1_pos2+1:tag2_pos1].strip()

