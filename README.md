CASLIB.PY
=========

A library to support OAuth, SAML, and CAS Clients as provided from a JASIG-CAS(3.5-4.0.0+) server
Written in python using requests

_Requirements_
- requests
- CAS Server
  - cas-server-support-oauth (Required for OAuth support)
  - cas-server-support-saml (Required for SAML support)

AUTHOR
======
Steven Gregory - iPlant Collaborative © 2012-2014
CONTACT: sgregory@iplantcollaborative.org


PREFACE
-------
caslib.py was initially built for a specific purpose, to add cas to a pre-existing authentication system (in Django).
The authentication system used token-based sessions that have a timeout, and the user was required to reauthenticate to renew the token.
As caslib.py has been developled it has been used as a robust CAS library for multiple projects within the iPlant Collaborative without issues,
with that being said this implementation is not guaranteed to work for your implementation of CAS.

The documentation on CAS is getting better, to learn about any of these protocols, visit: http://jasig.github.io/cas/4.0.0/index.html
CASLIB.PY HISTORY
=================
[1.0] - caslib.py initial development complete

caslib.py was initially developed for Atmosphere, an AJAX based web application for iPlant Collaborative.
In the first iteration of the library it served only two primary functions:
* Validating a ticket after a CAS login (aka BASIC AUTHENTICATION)
* Validating a proxyTicket and it's associated user (aka RE-AUTHENTICATION BY PROXY)

[2.0] - caslib.py refactored to include support multiple 'Client', 'Response' protocols

If supported by your CAS Server, caslib.py now includes support for:
* CAS authentication (Basic & through Proxy)
* SAML authentication (Basic ONLY)
* OAUTH 2.0 authentication

CAS AUTHENTICATION
====================

Option 1: Basic Authentication
-------

If your application requires authenticating the user once, caslib.py is great!
- Redirect your 'login' button/path to the CAS servers login
  Ex: CAS login path

        CASLoginURL = https://path.to_cas_server.org/cas/login?service=https://path.to/CAS_serviceValidater?sendback=/application/

  NOTE: The sendback parameter allows you to redirect the authenticated user to the endpoint they selected.  A race condition may occur if multiple users attempt to access multiple endpoints on a website.
- When your app receives a request with a "ticket" in the query string, CAS is sending you an authenticated user.
- To validate the ticket:

  ```python
    cas_client = CASClient("https://path.to_cas_server.org",
                           "https://path.to_cas_server.org/CAS_serviceValidater?sendback=/application/",
                           )
    ticket_from_cas = request.GET['ticket']
    cas_response = cas_client.cas_serviceValidate(ticket_from_cas)
    #cas_response object
    (truth, user) = (cas_response.success, cas_response.user)
    if (truth) redirect(user,sendback) else redirect(CASLoginURL)
  ```

Option 2: Re-Authentication of the user by proxy
-------


DJANGO IMPLEMENTATION
------------

caslib.py was written to be integrated with the python web framework, Django. Django is not required to use caslib.py. A more detailed description of this can be found at GENERIC USAGE

Below is an example of the settings, urls.py, views.py, and models.py that are required for caslib.py to function properly:

###settings.py###
  ```python
    ##These settings will be used often
    CAS_SERVER = "https://path.to_cas_server.org"
    SERVICE_URL = "https://path.to/CAS_serviceValidater?sendback=/application/"
    PROXY_URL = "https://path.to/CAS_proxyUrl"
    PROXY_CALLBACK_URL = "https://path.to/CAS_proxyCallback"
    SELF_SIGNED_CERT = False
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
   def get_cas_client():
       """
       This is how you initialize a CAS Client
       """
       return CASClient(settings.CAS_SERVER,
               settings.SERVICE_URL,
               proxy_url=settings.PROXY_URL,
               proxy_callback=settings.PROXY_CALLBACK_URL,
               self_signed_cert=settings.SELF_SIGNED_CERT)
    def cas_validateTicket(request):
        """
        Method expects 2 GET parameters: 'ticket' & 'sendback'
        After a CAS Login:
        Redirects the request based on the GET param 'ticket'
        Unauthorized Users are redirected to '/' In the event of failure.
        Authorized Users are redirected to the GET param 'sendback'
        """

        redirect_logout_url = settings.REDIRECT_URL+"/login/"
        no_user_url = settings.REDIRECT_URL + "/no_user/"
        logger.debug('GET Variables:%s' % request.GET)
        ticket = request.GET.get('ticket', None)
        sendback = request.GET.get('sendback', None)

        if not ticket:
            logger.info("No Ticket received in GET string "
                        "-- Logout user: %s" % redirect_logout_url)
            return HttpResponseRedirect(redirect_logout_url)

        logger.debug("ServiceValidate endpoint includes a ticket."
                     " Ticket must now be validated with CAS")

        # ReturnLocation set, apply on successful authentication

        caslib = get_cas_client()
        caslib.service_url = _set_redirect_url(sendback, request)

        cas_response = caslib.cas_serviceValidate(ticket)
        if not cas_response.success:
            logger.debug("CAS Server did NOT validate ticket:%s"
                         " and included this response:%s"
                         % (ticket, cas_response.object))
            return HttpResponseRedirect(redirect_logout_url)
        if not cas_response.user:
            logger.debug("User attribute missing from cas response!"
                         "This may require a fix to caslib.py")
            return HttpResponseRedirect(redirect_logout_url)
        if not cas_response.proxy_granting_ticket:
            logger.error("""Proxy Granting Ticket missing!
                Possible Causes:
                  * ServerName variable is wrong in /etc/apache2/apache2.conf
                  * Proxy URL does not exist
                  * Proxy URL is not a valid RSA-2/VeriSigned SSL certificate
                  * /etc/host and hostname do not match machine.""")
            return HttpResponseRedirect(redirect_logout_url)

        #Implementation specific - Find matching ticket && user in Database
        updated = updateUserProxy(user, pgtIou)
        if not updated:
            return HttpResponseRedirect(redirect_logout_url)
        logger.info("Updated proxy for <%s> -- Auth success!" % user)
        logger.info("Create tokens, do implementation specific stuff"
                    ", return to: %s" % return_to)
        return HttpResponseRedirect(return_to)

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

GENERIC IMPLEMENTATION
-------------
caslib.py can be used on any server, provided that the server has a method for storing and recalling users, IOUs, and IDs and includes the 3 Endpoints described below:

_(USER,IOU,ID) Storage methods:_
- Database:
  All that is needed is one table to hold three string values:

      caslib_userProxy
      ----------------
      * username
      * proxyIOU
      * proxyTicket
      NOTE: Username is initially null, IOU and Ticket always stored @ cas_proxy_url BEFORE returning username to cas_service_url


  Endpoints:
  1. cas_proxy_url - Create a new entry in the Database ("",IOU,ID) where IOU and ID are in the GET request
  2. cas_proxy_callback - a blank page, nothing is required here except that the page is valid.
  3. cas_service_url - In addition to validating the ticket, lookup the IOU in DB (provided in cas_proxy_url) and record associated username to the database - (username, IOU, ID)

OAUTH Authentication
===================
    OAuth Authentication is very similar to CAS Authentication, the difference
    is in the values you request from the client/response objects.

###settings.py###
  ```python
    ##These settings will be used often
    CAS_SERVER = "https://path.to_cas_server.org"
    OAUTH_CLIENT_KEY = "cas_registered_client"
    OAUTH_CLIENT_SECRET = "shh_its_a_secret"
    #This URL exists on YOUR server
    OAUTH_CLIENT_CALLBACK = SERVER_URL + "/oauth2.0/callbackAuthorize"
  ```
###views.py###
  ```python
  def get_cas_oauth_client():
      o_client = OAuthClient(settings.CAS_SERVER,
              settings.OAUTH_CLIENT_CALLBACK,
              settings.OAUTH_CLIENT_KEY,
              settings.OAUTH_CLIENT_SECRET)
      return o_client
  def o_login_redirect(request):
      oauth_client = get_cas_oauth_client()
      url = oauth_client.authorize_url()
      return HttpResponseRedirect(url)
  def o_callback_authorize(request):
      if 'code' not in request.GET:
          logger.info(request.__dict__)
          #TODO - Maybe: Redirect into a login
          return HttpResponse("")

      oauth_client = get_cas_oauth_client()
      oauth_code = request.GET['code']

      #Exchange code for ticket
      access_token, expiry_date = oauth_client.get_access_token(oauth_code)

      if not access_token:
          logger.info("The Code %s is invalid/expired. Attempting another login."
                      % oauth_code)
          return o_login_redirect(request)

      #Exchange token for profile
      user_profile = oauth_client.get_profile(access_token)

      if not user_profile or "id" not in user_profile:
          logger.error("AccessToken is producing an INVALID profile! "
                       "Check the CAS server and caslib.py for more information.")
          #NOTE: Make sure this redirects the user OUT of the loop!
          return login(request)

      #ASSERT: A valid OAuth token gave us the Users Profile.
      # Now create an AuthToken and return it
      username = user_profile["id"]
      #Implementation specific.. create an API token and return
      # it to the user...
      return HttpResponseRedirect("my.app.com/application")
  ```

SAML Authentication
===================

###settings.py###
  ```python
    ##These settings will be used often
    CAS_SERVER = "https://path.to_cas_server.org"
    OAUTH_CLIENT_KEY = "cas_registered_client"
    OAUTH_CLIENT_SECRET = "shh_its_a_secret"
    #This URL exists on YOUR server
    OAUTH_CLIENT_CALLBACK = SERVER_URL + "/oauth2.0/callbackAuthorize"
  ```
###views.py###
```python
def get_saml_client():
    s_client = SAMLClient(settings.CAS_SERVER,
            settings.SERVER_URL,
            auth_prefix='/castest')
    return s_client

def saml_validateTicket(request):
    """
    Method expects 2 GET parameters: 'ticket' & 'sendback'
    After a CAS Login:
    Redirects the request based on the GET param 'ticket'
    Unauthorized Users are redirected to '/' In the event of failure.
    Authorized Users are redirected to the GET param 'sendback'
    """

    redirect_logout_url = settings.REDIRECT_URL+"/login/"
    no_user_url = settings.REDIRECT_URL + "/no_user/"
    logger.debug('GET Variables:%s' % request.GET)
    ticket = request.GET.get('ticket', None)
    sendback = request.GET.get('sendback', None)

    if not ticket:
        logger.info("No Ticket received in GET string "
                    "-- Logout user: %s" % redirect_logout_url)
        return HttpResponseRedirect(redirect_logout_url)

    logger.debug("ServiceValidate endpoint includes a ticket."
                 " Ticket must now be validated with SAML")

    # ReturnLocation set, apply on successful authentication

    saml_client = get_saml_client()
    saml_response = saml_client.saml_serviceValidate(ticket)
    if not saml_response.success:
        logger.debug("CAS Server did NOT validate ticket:%s"
                     " and included this response:%s"
                     % (ticket, saml_response.xml))
        return HttpResponseRedirect(redirect_logout_url)

    #Implementation specific... Create API token for
    # saml_response.user
    return HttpResponseRedirect("my.app.com/application")
```
