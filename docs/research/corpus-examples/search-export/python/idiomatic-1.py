"""
Fragment from the SAME Django asset-management app and file as
vulnerable-1.py (asset/views.py), showing the idiomatic counterpart:
ordinary search/filter fields (`name`, `project`, `business`) reach
the ORM through `.filter(Q(...))`, which parameter-binds values
rather than interpolating them into raw SQL. Contrast with
vulnerable-1.py's `.extra(where=...)` bulk-action path in the same
class hierarchy, which bypasses this same ORM's binding for an
`IN (...)` clause built from request data.

See this directory's manifest.yaml for the full source attribution
and commit (same commit as vulnerable-1.py, since both come from the
same file).
"""
from django.db.models import Q
from django.views.generic import ListView


class AssetList(ListView):
    """
    资产信息 查询功能 (asset search/filter list view)
    """

    def get_queryset(self):
        name = Names.objects.get(username=self.request.user)
        self.queryset = super().get_queryset()
        for i in self.queryset:
            projects = AssetInfo.objects.get(hostname=i).project
            project_obj = AssetProject.objects.get(projects=projects)
            hasperm = name.has_perm('read_assetproject', project_obj)
            if not hasperm:
                self.queryset.delete(i)

        # IDIOMATIC: search/filter values from the request go through
        # Q()/.filter(), which binds them as query parameters instead
        # of interpolating them into a SQL string.
        if self.request.GET.get('name'):
            query = self.request.GET.get('name', None)
            self.queryset = self.queryset.filter(
                Q(network_ip=query) | Q(hostname=query) | Q(inner_ip=query) | Q(project__projects=query)
            ).order_by('-id')
        elif self.request.GET.get('project'):
            project = self.request.GET.get('project', None)
            business = self.request.GET.get('business', None)
            if business is not None:
                pro = AssetProject.objects.get(id=int(project)).projects
                self.queryset = self.queryset.filter(
                    Q(project__projects=pro), Q(business__business=business)
                ).order_by('-id')
            else:
                self.queryset = self.queryset.filter(Q(project__projects=project)).order_by('-id')
        return self.queryset
