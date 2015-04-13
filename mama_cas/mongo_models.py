#!/usr/bin/env python
# encoding: utf-8

import logging
import re

import requests
from django.conf import settings
from django.utils.timezone import now

import mongoengine as me
from mongoengine.django.mongo_auth.models import get_user_document

from mama_cas.request import SingleSignOutRequest

logger = logging.getLogger(__name__)
user_document = get_user_document()


class MTicket(object):

    TICKET_EXPIRE = getattr(settings, 'MAMA_CAS_TICKET_EXPIRE', 90)
    TICKET_RAND_LEN = getattr(settings, 'MAMA_CAS_TICKET_RAND_LEN', 32)
    TICKET_RE = re.compile("^[A-Z]{2,3}-[0-9]{10,}-[a-zA-Z0-9]{%d}$" % TICKET_RAND_LEN)

    ticket = me.StringField(max_length=255, unique=True)
    user = me.ReferenceField(user_document)
    expires = me.DateTimeField()
    consumed = me.DateTimeField(null=True)

    @property
    def name(self):
        return 'ticket'

    def consume(self):
        """
        Consume a ``Ticket`` by populating the ``consumed`` field with
        the current datetime. A consumed ``Ticket`` is invalid for future
        authentication attempts.
        """
        self.consumed = now()
        self.save()

    def is_consumed(self):
        """
        Check a ``Ticket``s consumed state. Return ``True`` if the ticket is
        consumed, and ``False`` otherwise.
        """
        return self.consumed is not None

    def is_expired(self):
        """
        Check a ``Ticket``s expired state. Return ``True`` if the ticket is
        expired, and ``False`` otherwise.
        """
        return self.expires <= now()


class MServiceTicket(MTicket, me.Document):
    TICKET_PREFIX = 'ST'

    service = me.StringField(max_length=255)
    primary = me.BooleanField(default=False)

    meta = {
        'collection': 'service_ticket'
    }

    def is_primary(self):
        """
        Check the credential origin for a ``ServiceTicket``. If the ticket was
        issued from the presentation of the user's primary credentials,
        return ``True``, otherwise return ``False``.
        """
        if self.primary:
            return True
        return False

    def request_sign_out(self):
        """
        Send a POST request to the ``ServiceTicket``s service URL to
        request sign-out. The remote session is identified by the
        service ticket string that instantiated the session.
        """
        request = SingleSignOutRequest(context={'ticket': self})
        try:
            resp = requests.post(self.service, data=request.render_content(),
                                 headers=request.headers())
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.warning("Single sign-out request to %s returned %s" %
                           (self.service, e))
        else:
            logger.debug("Single sign-out request sent to %s" % self.service)


class MProxyTicket(MTicket, me.Document):
    TICKET_PREFIX = 'PT'

    service = me.StringField(max_length=255)
    granted_by_pgt = me.ReferenceField('ProxyGrantingTicket')

    meta = {
        'collection': 'proxy_ticket'
    }


class MProxyGrantingTicket(MTicket, me.Document):
    TICKET_PREFIX = 'PGT'
    IOU_PREFIX = 'PGTIOU'
    TICKET_EXPIRE = getattr(settings, 'SESSION_COOKIE_AGE')

    iou = me.StringField(max_length=255, unique=True)
    granted_by_st = me.ReferenceField('MServiceTicket', null=True)
    granted_by_pt = me.ReferenceField('MProxyTicket', null=True)

    meta = {
        'collection': 'proxy_granting_ticket'
    }
