CASLIB.PY
=========

A CAS authentication library written in python using httplib2  

_Requirements_
- httplib2
- CAS Server

AUTHOR
======
Steven Gregory - iPlant Collaborative (C) 2012  
CONTACT: esteve@iplantcollaborative.org  


ABOUT CASLIB.PY
=================
caslib.py was initially developed for Atmosphere, an AJAX based web application for iPlant Collaborative.  
caslib.py serves two functions:
1. Validating a ticket after a CAS login (see BASIC AUTHENTICATION)
2. Validating a proxyTicket and it's associated user (see RE-AUTHENTICATION BY PROXY)

BASIC AUTHENTICATION
====================
If your application requires authenticating the user once, caslib.py is great!

- Redirect your 'login' button/path to the CAS servers login 
  Ex: CAS login path
    https://path.to.cas_server/cas/login?service=https://path.to/CAS_serviceValidater?sendback=/application/
  NOTE: I use the sendback parameter so that after the user is validated they can be sent to the correct endpoint, depending on your implementation this may or may not be useful.
- When your app receives a request with a "ticket" in the query string, CAS is sending you an authenticated user.
- To validate the ticket:
    casinit("https://path.to.cas_server","https://path.to/CAS_serviceValidater?sendback=/application/")
    (truth,user) = caslib.cas_serviceValidate(request.GET['ticket'])
    if (truth) redirect(user,sendback) else redirect(CAS login)

RE-AUTHENTICATION BY PROXY
==========================

PREFACE
-------
caslib.py was built for a specific purpose, to add cas to a pre-existing authentication system. The authentication system used token-based sessions that have a timeout, and in order to renew the token, the user needed to be reauthenticated by the web application.
The current implementation of caslib.py is meant to serve that purpose, and may or may not work for all implementations/back-end services wishing to use the proxy features.


DJANGO SETUP
------------

caslib.py was written to be integrated with the python web framework, Django. Django is not required to use caslib.py. A more detailed description of this can be found at GENERIC USAGE

Below is an example of the settings, urls.py, views.py, and models.py that are required for caslib.py to function properly:

###settings.py###
  ```python
    ##CASLIB
    import caslib
    CAS_SERVER = "https://path.to.cas_server"
    SERVICE_URL = "https://path.to/CAS_serviceValidater?sendback=/application/"
    PROXY_URL = "https://path.to/CAS_proxyUrl"
    PROXY_CALLBACK_URL = "https://path.to/CAS_proxyCallback"
    caslib.cas_init(CAS_SERVER, SERVICE_URL, PROXY_URL, PROXY_CALLBACK_URL)
  ```

###models.py###
  ```python
    class UserProxy(models.Model):
      """
      This model will be used to Map usernames, initially unknown, to proxy IOU ID ticket pairs
      """
      username = models.CharField(max_length=128, blank=True, null=True)
      proxyIOU = models.CharField(max_length=40)
      proxyTicket = models.CharField(max_length=70)
  ```

###urls.py###
  ```python
    #This URL validates the ticket returned after CAS login
    (r'^CAS_serviceValidater', 'casclient.views.cas_validateTicket'),
    #This URL is a dummy callback
    (r'^CAS_proxyCallback', 'casclient.views.cas_proxyCallback'),
    #This URL records Proxy IOU & ID
    (r'^CAS_proxyUrl', 'casclient.views.cas_storeProxyIOU_ID'),
  ```

###views.py###
  ```python
   def cas_validateTicket(request):
      """
      CAS Login : Phase 2/3 After returning from a CAS Login, this request will contain a ticket
      cas_serviceValidate is called to validate the user's ticket
      and the user is returned to 'sendback' (Authorized) or 'login' (Unauthorized) screen
      (Optional - Phase 3/3 - With the username and proxyTicket, a user can be re-authorized.)
      """
      if not request.GET.has_key('ticket'):
        return HttpResponseRedirect('/')
      casTuple = caslib.cas_serviceValidate(request.GET['ticket'])
      (truth, user, pgtIou) = casTuple if len(casTuple) == 3 else (casTuple[0], casTuple[1],"")
      if not truth or not user:
        return HttpResponseRedirect("/")
      if pgtIou and pgtIou != "":
        userProxy = UserProxy.objects.get(proxyIOU=pgtIou)
        userProxy.username = user
        userProxy.save()
      return HttpResponseRedirect(request.GET['sendback']) if getToken(request,request.META['HTTP_X_AUTH_USER'],None) else HttpResponseRedirect("/")

    def cas_storeProxyIOU_ID(request):
        """
        Any request to the proxy url will contain the PROXY-TICKET IOU and ID
        IOU and ID are mapped to a DB so they can be used later
        """
        if "pgtIou" in request.GET and "pgtId" in request.GET:
          proxy = UserProxy(proxyIOU=request.GET["pgtIou"], proxyTicket=request.GET["pgtId"])
          proxy.save()
        return HttpResponse("Received proxy request. Thank you.")

    def cas_proxyCallback(request):
        """
        This is a placeholder for a proxyCallback service, needed for CAS authentication
        """
        return HttpResponse("I am at a RSA-2 or VeriSigned SSL Cert. website, and therefore a valid proxy.")
    def login(request):
        """
        CAS Login : Phase 1/3 Call CAS Login
        """
        #Form Sets 'next' when user clicks login 
        if 'next' in request.POST:
           url = CAS_SERVER+"/cas/login?service="+"https://my.djangoserver.org/CAS_serviceValidater?sendback=/application/"
           return HttpResponseRedirect(url)
        #After CAS login, he will hit 'cas_getTicket'
        else:
           template = get_template('application/login.html')
  ```

GENERIC USAGE
=============
caslib.py can be used on any server, provided that the server has a method for storing and recalling users, IOUs, and IDs and includes the 3 Endpoints described below:

_(USER,IOU,ID) Storage methods:_  
- Database:
  All that is needed is one table with three VARCHARs:

  caslib_userProxy
  ----------------
  * username (null is OK, IOU and Ticket always stored BEFORE username)
  * proxyIOU
  * proxyTicket

  Endpoints:
  1.  cas_proxy_url - Create a new entry in the Database ("",IOU,ID) where IOU and ID are in the GET request
  2.  cas_proxy_callback - a blank page, nothing is required here except that the page is valid.
  3.  cas_service_url - In addition to validating the ticket, lookup the IOU in DB (provided in cas_proxy_url) and record associated username to the database - (NULL, IOU, ID) 