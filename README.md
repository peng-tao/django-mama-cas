Quickstart
========

Install with `pip`_::
```
   $ pip install -e https://github.com/alvinyao/django-mama-cas.git@mongo#egg=django-mama-cas
```

Add to ``INSTALLED_APPS`` and run ``migrate``::

```
   INSTALLED_APPS += ('mama_cas',)
```

Include the URLs::

```
   urlpatterns += patterns('', (r'', include('mama_cas.urls')))
```
