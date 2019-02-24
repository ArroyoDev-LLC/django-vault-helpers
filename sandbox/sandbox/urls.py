from django.db import connection
from django.conf.urls import include, url
from django.contrib import admin
from django.http import HttpResponse
import json
import time


def test_view(request):
    # Close the connection to force a reconnect
    connection.close()
    connection.settings_dict.reset_credentials()

    time.sleep(1)

    with connection.cursor() as c:
        c.execute('SELECT CURRENT_USER, SESSION_USER;')
        row = json.dumps(c.fetchone())
    return HttpResponse(row)


urlpatterns = (
    url(r'^i18n/', include('django.conf.urls.i18n')),
    url(r'^admin/', admin.site.urls),
    url(r'^', test_view),
)
