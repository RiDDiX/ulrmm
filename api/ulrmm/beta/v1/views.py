# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django_filters import (
    DateTimeFromToRangeFilter,
    FilterSet,
    NumberFilter,
    NumericRangeFilter,
)
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated

from agents.models import Agent
from agents.permissions import AgentPerms
from clients.models import Client, Site
from clients.permissions import ClientsPerms, SitesPerms

from .serializers import (
    ClientSerializer,
    DetailAgentSerializer,
    ListAgentSerializer,
    SiteSerializer,
)


class BetaPagination(PageNumberPagination):
    max_page_size = 1000
    page_size_query_param = "page_size"
    page_size = 100


class AgentFilter(FilterSet):
    client_id = NumberFilter(method="client_id_filter")
    last_seen_range = DateTimeFromToRangeFilter(field_name="last_seen")
    patches_last_installed_range = DateTimeFromToRangeFilter(
        field_name="patches_last_installed"
    )
    total_ram_range = NumericRangeFilter(field_name="total_ram")

    class Meta:
        model = Agent
        fields = (
            ["id", "hostname", "agent_id", "operating_system", "plat"]
            + ["monitoring_type", "needs_reboot", "logged_in_username"]
            + ["last_logged_in_user", "alert_template", "site", "policy"]
            + ["last_seen_range", "total_ram_range", "patches_last_installed_range"]
        )

    def client_id_filter(self, queryset, name, value):
        return queryset.filter(site__client__id=value) if value else queryset


class _ReadEdit(viewsets.ModelViewSet):
    # the beta api never creates or deletes
    http_method_names = ["get", "put"]


class _PagedReadEdit(_ReadEdit):
    pagination_class = BetaPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    ordering_fields = ["id"]
    ordering = ["id"]


class AgentViewSet(_PagedReadEdit):
    permission_classes = [IsAuthenticated, AgentPerms]
    search_fields = ["hostname", "services"]
    filterset_class = AgentFilter
    queryset = Agent.objects.all()

    def check_permissions(self, request):
        # AgentPerms reads the agent from the url kwargs
        agent_id = request.query_params.get("agent_id")
        if agent_id is not None:
            self.kwargs["agent_id"] = agent_id
        super().check_permissions(request)

    def get_permissions(self):
        if self.request.method != "POST":
            return super().get_permissions()
        return [IsAuthenticated()]

    def get_serializer_class(self):
        detail = bool(self.kwargs) and self.kwargs["pk"]
        return DetailAgentSerializer if detail else ListAgentSerializer


class ClientViewSet(_ReadEdit):
    serializer_class = ClientSerializer
    permission_classes = [IsAuthenticated, ClientsPerms]
    queryset = Client.objects.all()


class SiteViewSet(_PagedReadEdit):
    serializer_class = SiteSerializer
    search_fields = ["name"]
    permission_classes = [IsAuthenticated, SitesPerms]
    queryset = Site.objects.all()
