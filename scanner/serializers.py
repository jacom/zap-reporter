from rest_framework import serializers
from .models import ScanTarget, Scan, Alert, MonthlySummary


class ScanTargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanTarget
        fields = '__all__'


class AlertSerializer(serializers.ModelSerializer):
    severity = serializers.CharField(source='get_risk_display', read_only=True)

    class Meta:
        model = Alert
        fields = '__all__'


class ScanSerializer(serializers.ModelSerializer):
    target_name = serializers.CharField(source='target.name', read_only=True)
    target_url = serializers.CharField(source='target.url', read_only=True)
    total_alerts = serializers.IntegerField(read_only=True)
    tool_display = serializers.CharField(source='get_tool_display', read_only=True)

    class Meta:
        model = Scan
        fields = '__all__'


class MonthlySummarySerializer(serializers.ModelSerializer):
    target_name = serializers.CharField(source='target.name', read_only=True)

    class Meta:
        model = MonthlySummary
        fields = '__all__'
