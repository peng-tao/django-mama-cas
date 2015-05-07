from __future__ import unicode_literals

from datetime import timedelta
import logging
import os
import time

from django.conf import settings
from django.db import models
from django.utils.crypto import get_random_string
from django.utils.encoding import python_2_unicode_compatible
from django.utils.http import same_origin
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _

from mongoengine import Q
import requests

from mama_cas.compat import gevent
from mama_cas.exceptions import BadPgt
from mama_cas.exceptions import InvalidProxyCallback
from mama_cas.exceptions import InvalidRequest
from mama_cas.exceptions import InvalidService
from mama_cas.exceptions import InvalidTicket
from mama_cas.utils import add_query_params
from mama_cas.utils import is_scheme_https
from mama_cas.utils import clean_service_url
from mama_cas.utils import is_valid_service_url

from mama_cas.mongo_models import (
    MProxyTicket, MServiceTicket, MProxyGrantingTicket)

if gevent:
    from gevent.pool import Pool
    from gevent import monkey
    monkey.patch_all(thread=False, select=False)


logger = logging.getLogger(__name__)


class TicketManager(object):

    def create_ticket(self, ticket=None, **kwargs):
        """
        Create a new ``Ticket``. Additional arguments are passed to the
        ``create()`` function. Return the newly created ``Ticket``.
        """
        if not ticket:
            ticket = self.create_ticket_str()
        if 'service' in kwargs:
            kwargs['service'] = clean_service_url(kwargs['service'])
        if 'expires' not in kwargs:
            expires = now() + timedelta(seconds=self.model.TICKET_EXPIRE)
            kwargs['expires'] = expires
        t = self.create(ticket=ticket, **kwargs)
        logger.debug("Created %s %s" % (t.name, t.ticket))
        return t

    def create_ticket_str(self, prefix=None):
        """
        Generate a sufficiently opaque ticket string to ensure the ticket is
        not guessable. If a prefix is provided, prepend it to the string.
        """
        if not prefix:
            prefix = self.model.TICKET_PREFIX
        return "%s-%d-%s" % (prefix, int(time.time()),
                             get_random_string(length=self.model.TICKET_RAND_LEN))

    def validate_ticket(self, ticket, service, renew=False):
        """
        Given a ticket string and service identifier, validate the
        corresponding ``Ticket``. If validation succeeds, return the
        ``Ticket``. If validation fails, raise an appropriate error.

        If ``renew`` is provided, the validation will only succeed if the
        ticket was issued from the presentation of the user's primary
        credentials.
        """
        if not ticket:
            raise InvalidRequest("No ticket string provided")

        if not self.model.TICKET_RE.match(ticket):
            raise InvalidTicket("Ticket string %s is invalid" % ticket)

        try:
            t = self.model.objects.get(ticket=ticket)
        except self.model.DoesNotExist:
            raise InvalidTicket("Ticket %s does not exist" % ticket)

        if t.is_consumed():
            raise InvalidTicket("%s %s has already been used" %
                                (t.name, ticket))
        t.consume()

        if t.is_expired():
            raise InvalidTicket("%s %s has expired" % (t.name, ticket))

        if not service:
            raise InvalidRequest("No service identifier provided")

        if not is_valid_service_url(service):
            raise InvalidService("Service %s is not a valid %s URL" %
                                 (service, t.name))

        if not same_origin(t.service, service):
            raise InvalidService("%s %s for service %s is invalid for service "
                                 "%s" % (t.name, ticket, t.service, service))

        if renew and not t.is_primary():
            raise InvalidTicket("%s %s was not issued via primary "
                                "credentials" % (t.name, ticket))

        logger.debug("Validated %s %s" % (t.name, ticket))
        return t

    def delete_invalid_tickets(self):
        """
        Delete consumed or expired ``Ticket``s that are not referenced
        by other ``Ticket``s. Invalid tickets are no longer valid for
        authentication and can be safely deleted.

        A custom management command is provided that executes this method
        on all applicable models by running ``manage.py cleanupcas``.
        """
        for ticket in self.filter(Q(consumed__exists=True) |
                                  Q(expires__lte=now())).order_by('-expires'):
            try:
                ticket.delete()
            except models.ProtectedError:
                pass

    def consume_tickets(self, user):
        """
        Consume all valid ``Ticket``s for a specified user. This is run
        when the user logs out to ensure all issued tickets are no longer
        valid for future authentication attempts.
        """
        for ticket in self.filter(user=user, consumed__exists=False,
                                  expires__gt=now()):
            ticket.consume()

    def get_query_set(self):
        return self.model.objects

    def get_empty_query_set(self):
        return self.model.objects.none()


@python_2_unicode_compatible
class Ticket(object):
    """
    ``Ticket`` is an abstract base class implementing common methods
    and fields for CAS tickets.
    """

    def __str__(self):
        return self.ticket


class ServiceTicketManager(TicketManager, models.Manager):

    def contribute_to_class(self, model, name):
        super(ServiceTicketManager, self).contribute_to_class(model, name)
        self.dj_model = self.model
        self.model = MServiceTicket

    def request_sign_out(self, user):
        """
        Send a single sign-out request to each service accessed by a
        specified user. This is called at logout when single sign-out
        is enabled.

        If gevent is installed, asynchronous requests will be sent.
        Otherwise, synchronous requests will be sent. Setting
        ``MAMA_CAS_ASYNC_CONCURRENCY`` limits concurrent requests for
        a logout event to the specified value.
        """
        def spawn(ticket, pool=None):
            if pool is not None:
                return pool.spawn(ticket.request_sign_out)
            return gevent.spawn(ticket.request_sign_out)

        tickets = list(self.filter(user=user, consumed__gte=user.last_login))

        if gevent:
            size = getattr(settings, 'MAMA_CAS_ASYNC_CONCURRENCY', 2)
            pool = Pool(size) if size else None
            sign_out_requests = [spawn(t, pool=pool) for t in tickets]
            gevent.joinall(sign_out_requests)
        else:
            for ticket in tickets:
                ticket.request_sign_out()


class ServiceTicket(Ticket, models.Model):
    """
    (3.1) A ``ServiceTicket`` is used by the client as a credential to
    obtain access to a service. It is obtained upon a client's presentation
    of credentials and a service identifier to /login.
    """
    objects = ServiceTicketManager()

    class Meta:
        verbose_name = _('service ticket')
        verbose_name_plural = _('service tickets')


class ProxyTicketManager(TicketManager, models.Manager):

    def contribute_to_class(self, model, name):
        super(ProxyTicketManager, self).contribute_to_class(model, name)
        self.dj_model = self.model
        self.model = MProxyTicket


class ProxyTicket(Ticket, models.Model):
    """
    (3.2) A ``ProxyTicket`` is used by a service as a credential to obtain
    access to a back-end service on behalf of a client. It is obtained upon
    a service's presentation of a ``ProxyGrantingTicket`` and a service
    identifier.
    """
    objects = ProxyTicketManager()

    class Meta:
        verbose_name = _('proxy ticket')
        verbose_name_plural = _('proxy tickets')


class ProxyGrantingTicketManager(TicketManager, models.Manager):

    def contribute_to_class(self, model, name):
        super(ProxyGrantingTicketManager, self).contribute_to_class(model, name)
        self.dj_model = self.model
        self.model = MProxyGrantingTicket

    def create_ticket(self, pgturl, **kwargs):
        """
        When a ``pgtUrl`` parameter is provided to ``/serviceValidate`` or
        ``/proxyValidate``, attempt to create a new ``ProxyGrantingTicket``.
        If PGT URL validation succeeds, create and return the
        ``ProxyGrantingTicket``. If validation fails, return ``None``.
        """
        pgtid = self.create_ticket_str()
        pgtiou = self.create_ticket_str(prefix=self.model.IOU_PREFIX)
        try:
            self.validate_callback(pgturl, pgtid, pgtiou)
        except InvalidProxyCallback as e:
            logger.warning("%s %s" % (e.code, e))
            return None
        else:
            # pgtUrl validation succeeded, so create a new PGT with the
            # previously generated ticket strings
            return super(ProxyGrantingTicketManager, self).create_ticket(ticket=pgtid,
                                                                         iou=pgtiou,
                                                                         **kwargs)

    def validate_callback(self, url, pgtid, pgtiou):
        """
        Verify the provided proxy callback URL. This verification process
        requires three steps:

        1. The URL scheme must be HTTPS
        2. The SSL certificate must be valid and its name must match that
           of the service
        3. The callback URL must respond with a 200 or 3xx response code

        It is not required for validation that 3xx redirects be followed.
        """
        # Ensure the scheme is HTTPS before proceeding
        if not is_scheme_https(url):
            raise InvalidProxyCallback("Proxy callback %s is not HTTPS" % url)

        # Connect to proxy callback URL, checking the SSL certificate
        url_params = add_query_params(url, {'pgtId': pgtid, 'pgtIou': pgtiou})
        verify = os.environ.get('REQUESTS_CA_BUNDLE', True)
        try:
            r = requests.get(url_params, verify=verify, timeout=3.0)
        except requests.exceptions.SSLError:
            msg = "SSL cert validation failed for proxy callback %s" % url
            raise InvalidProxyCallback(msg)
        except requests.exceptions.ConnectionError:
            msg = "Error connecting to proxy callback %s" % url
            raise InvalidProxyCallback(msg)
        except requests.exceptions.Timeout:
            msg = "Timeout connecting to proxy callback %s" % url
            raise InvalidProxyCallback(msg)

        # Check the returned HTTP status code
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            msg = "Proxy callback %s returned %s" % (url, e)
            raise InvalidProxyCallback(msg)

    def validate_ticket(self, ticket, service):
        """
        Given a ticket string and service identifier, validate the
        corresponding ``Ticket``. If validation succeeds, return the
        ``Ticket``. If validation fails, raise an appropriate error.
        """
        if not ticket:
            raise InvalidRequest("No ticket string provided")

        if not service:
            raise InvalidRequest("No service identifier provided")

        if not self.model.TICKET_RE.match(ticket):
            raise InvalidTicket("Ticket string %s is invalid" % ticket)

        try:
            t = self.model.objects.get(ticket=ticket)
        except self.model.DoesNotExist:
            raise BadPgt("Ticket %s does not exist" % ticket)

        if t.is_consumed():
            raise InvalidTicket("%s %s has already been used" %
                                (t.name, ticket))

        if t.is_expired():
            raise InvalidTicket("%s %s has expired" % (t.name, ticket))

        if not is_valid_service_url(service):
            raise InvalidService("Service %s is not a valid %s URL" %
                                 (service, t.name))

        logger.debug("Validated %s %s" % (t.name, ticket))
        return t


class ProxyGrantingTicket(Ticket, models.Model):
    """
    (3.3) A ``ProxyGrantingTicket`` is used by a service to obtain proxy
    tickets for obtaining access to a back-end service on behalf of a
    client. It is obtained upon validation of a ``ServiceTicket`` or a
    ``ProxyTicket``.
    """
    objects = ProxyGrantingTicketManager()

    class Meta:
        verbose_name = _('proxy-granting ticket')
        verbose_name_plural = _('proxy-granting tickets')
