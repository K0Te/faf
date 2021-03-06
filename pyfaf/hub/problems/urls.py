from django.conf.urls.defaults import *
from django.views.generic.simple import redirect_to

urlpatterns = patterns('pyfaf.hub.problems.views',
    url(r'^$', redirect_to, {'url': '/problems/hot/' }),

    url(r'^hot/$', 'hot'),
    url(r'^hot/(?P<os_release>[^/]+)/$', 'hot'),
    url(r'^hot/(?P<os_release>[^/]+)/(?P<associate>[^/]+)/$', 'hot'),
    url(r'^hot/(?P<os_release>[^/]+)/(?P<associate>[^/]+)/(?P<component>[^/]+)/$', 'hot'),

    url(r'^longterm/$', 'longterm'),
    url(r'^longterm/(?P<os_release>[^/]+)/$', 'longterm'),
    url(r'^longterm/(?P<os_release>[^/]+)/(?P<associate>[^/]+)/$', 'longterm'),
    url(r'^longterm/(?P<os_release>[^/]+)/(?P<associate>[^/]+)/(?P<component>[^/]+)/$', 'longterm'),

    url(r'^bthash/(?P<bthash>[a-fA-F0-9]+)/?$', 'bthash_forward'),

    url(r'^(?P<problem_id>\d+)/$', 'item'),
    url(r'^(?P<problem_id>\d+)/backtraces/$', 'backtraces'),
    url(r'^(?P<problem_id>\d+)/cluster/$', 'cluster'),
)
