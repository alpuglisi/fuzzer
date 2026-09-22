"""
Fragment from a Django asset-management app's bulk-action endpoint
(asset/views.py). See this directory's manifest.yaml for the full
source attribution and commit.

Shape: Django's ORM query-builder (`QuerySet.extra(where=...)`) is
handed a raw SQL fragment built by joining user-supplied, comma-
separated primary keys directly into an `IN (...)` clause -- an ORM
"escape hatch" misuse rather than the raw-string-concat-into-a-driver
shape already modeled elsewhere: the app otherwise uses the ORM
throughout, and injection slips in specifically through `.extra()`,
which bypasses the ORM's own parameter binding. See idiomatic-1.py
(same file, same app) for the safe `.filter(Q(...))` shape used
elsewhere in this exact class for ordinary search filtering.
"""
import json
from django.http import HttpResponse

from .models import AssetInfo


class AssetDel:
    """
    资产信息 删除 (asset bulk delete)
    """

    @staticmethod
    def post(request):
        ret = {'status': True, 'error': None}
        name = Names.objects.get(username=request.user)
        try:
            if request.POST.get('nid'):
                ids = request.POST.get('nid', None)
                project = AssetInfo.objects.get(id=ids).project
                project_obj = AssetProject.objects.get(projects=project)
                hasperm = name.has_perm('delete_assetproject', project_obj)
                if not hasperm:
                    ret['status'] = False
                    ret['error'] = "没有删除权限"
                    return HttpResponse(json.dumps(ret))
                else:
                    AssetInfo.objects.get(id=ids).delete()
            else:
                ids = request.POST.getlist('id', None)
                idstring = ','.join(ids)
                # VULNERABLE: `idstring` is untrusted request data joined
                # directly into a raw SQL fragment via .extra(where=...),
                # bypassing the ORM's parameter binding entirely. A
                # request whose `id[]` values aren't plain integers (or
                # that abuses the join itself) reaches this WHERE clause
                # unescaped.
                assets = AssetInfo.objects.extra(where=['id IN (' + idstring + ')'])
        except Exception as e:
            ret['status'] = False
            ret['error'] = str(e)
        return HttpResponse(json.dumps(ret))
