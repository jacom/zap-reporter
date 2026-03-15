from django.contrib import admin
from .models import ScanTarget, Scan, Alert, MonthlySummary


@admin.register(ScanTarget)
class ScanTargetAdmin(admin.ModelAdmin):
    list_display = ('name', 'url', 'created_at')
    search_fields = ('name', 'url')


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('target', 'scan_type', 'status', 'risk_score',
                    'high_count', 'medium_count', 'low_count', 'started_at')
    list_filter = ('status', 'scan_type')
    search_fields = ('target__name',)


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('name', 'risk', 'cvss_score', 'cwe_id', 'scan')
    list_filter = ('risk',)
    search_fields = ('name', 'url')


@admin.register(MonthlySummary)
class MonthlySummaryAdmin(admin.ModelAdmin):
    list_display = ('target', 'year_month', 'total_scans', 'avg_risk_score',
                    'high_count', 'medium_count')
