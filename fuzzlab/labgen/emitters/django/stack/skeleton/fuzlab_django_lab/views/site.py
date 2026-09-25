"""PicTrail's site layer (CC-LAB-0242, FR-LAB-160): the homepage, the
catalog of every page this build serves, and the link-preview API's client
page. Hand-written, checked-in skeleton code -- never generated per cell, so
it is byte-identical in every build and carries no vulnerability of its own.
"""

from django.shortcuts import render


def home(request):
    return render(request, "site/home.html")


def catalog(request):
    # Imported lazily: `urls.py` (the generated route accumulator) imports
    # this module, so a module-level import back into it would be circular.
    from fuzlab_django_lab.urls import CATALOG

    entries = [
        {"url": url, "cell_id": cell_id, "method": method}
        for url, cell_id, method, linkable in CATALOG
        if linkable
    ]
    return render(request, "site/catalog.html", {"entries": entries})


def upload_client(request):
    return render(request, "site/upload.html")
