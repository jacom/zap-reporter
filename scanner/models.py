import uuid
from django.db import models


class ScanTarget(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    url = models.URLField(max_length=500)
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.url})"


class Scan(models.Model):
    class ScanType(models.TextChoices):
        SPIDER = 'spider', 'Spider'
        ACTIVE = 'active', 'Active Scan'
        AJAX = 'ajax', 'Ajax Spider'
        FULL = 'full', 'Full Scan'

    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    class ToolSource(models.TextChoices):
        ZAP = 'zap', 'OWASP ZAP'
        TRIVY = 'trivy', 'Trivy'
        SONARQUBE = 'sonarqube', 'SonarQube'
        TESTSSL = 'testssl', 'testssl.sh'
        WAZUH = 'wazuh', 'Wazuh'
        OPENVAS = 'openvas', 'OpenVAS'
        NUCLEI  = 'nuclei',  'Nuclei'
        NMAP    = 'nmap',    'Nmap'
        HTTPX   = 'httpx',   'httpx Probe'
        SQLMAP  = 'sqlmap',  'sqlmap'
        DIRB    = 'dirb',    'Dir Brute Force (ffuf)'
        WPSCAN  = 'wpscan',  'WPScan (WordPress)'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='scans')
    scan_type = models.CharField(max_length=10, choices=ScanType.choices, default=ScanType.FULL)
    tool = models.CharField(max_length=20, choices=ToolSource.choices, default=ToolSource.ZAP)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    zap_scan_id = models.CharField(max_length=100, blank=True)
    tool_version = models.CharField(max_length=100, blank=True, default='')

    # Denormalized counts
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)

    risk_score = models.FloatField(default=0.0)
    exploit_count = models.IntegerField(default=0,
                                        help_text='Number of alerts with known public exploits')
    raw_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f"[{self.get_tool_display()}] {self.target.name} ({self.get_status_display()})"

    @property
    def total_alerts(self):
        return self.critical_count + self.high_count + self.medium_count + self.low_count + self.info_count

    def compute_risk_score(self):
        self.risk_score = (
            self.critical_count * 20 +
            self.high_count * 10 +
            self.medium_count * 5 +
            self.low_count * 1 +
            self.exploit_count * 5   # +5 per alert with public exploit
        )
        return self.risk_score

    def update_counts(self):
        alerts = self.alerts.all()
        self.critical_count = alerts.filter(risk=4).count()
        self.high_count = alerts.filter(risk=3).count()
        self.medium_count = alerts.filter(risk=2).count()
        self.low_count = alerts.filter(risk=1).count()
        self.info_count = alerts.filter(risk=0).count()
        self.exploit_count = alerts.filter(has_public_exploit=True).count()
        self.compute_risk_score()
        self.save(update_fields=['critical_count', 'high_count', 'medium_count',
                                 'low_count', 'info_count', 'exploit_count', 'risk_score'])


class Alert(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='alerts')
    alert_ref = models.CharField(max_length=50, blank=True)
    name = models.CharField(max_length=500)
    risk = models.IntegerField(default=0, help_text='0=Info, 1=Low, 2=Medium, 3=High, 4=Critical')
    confidence = models.IntegerField(default=0, help_text='0=FP, 1=Low, 2=Medium, 3=High')
    url = models.TextField(blank=True)
    param = models.CharField(max_length=500, blank=True)
    attack = models.TextField(blank=True)
    evidence = models.TextField(blank=True)
    description = models.TextField(blank=True)
    solution = models.TextField(blank=True)
    reference = models.TextField(blank=True)
    cwe_id = models.IntegerField(default=0)
    wasc_id = models.IntegerField(default=0)
    cvss_score = models.FloatField(default=0.0)
    cvss_vector = models.CharField(max_length=200, blank=True)
    tool = models.CharField(max_length=20, default='zap')
    owasp_category = models.CharField(max_length=10, blank=True,
                                      help_text='OWASP 2025 category e.g. A01, A03')
    cve_ids = models.JSONField(default=list, blank=True,
                               help_text='CVE IDs found/related to this alert (e.g. ["CVE-2021-44228"])')
    has_public_exploit = models.BooleanField(default=False,
                                             help_text='Public exploit available (Exploit-DB / CISA KEV)')
    in_cisa_kev = models.BooleanField(default=False,
                                      help_text='CVE in CISA Known Exploited Vulnerabilities catalog')
    exploit_refs = models.JSONField(default=list, blank=True,
                                    help_text='List of exploit references (CISA KEV, Exploit-DB IDs)')

    class Meta:
        ordering = ['-risk', '-cvss_score']

    def __str__(self):
        return f"{self.get_risk_display()} - {self.name}"

    RISK_LABELS = {0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}

    def get_risk_display(self):
        return self.RISK_LABELS.get(self.risk, 'Info')

    @property
    def severity(self):
        return self.get_risk_display()


class AlertAIAnalysis(models.Model):
    """AI-generated analysis for a unique vulnerability group within a scan."""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='ai_analyses')
    name = models.CharField(max_length=500)
    cwe_id = models.IntegerField(default=0)
    cvss_score = models.FloatField(default=0.0)
    risk = models.IntegerField(default=0)

    technical_explanation = models.TextField(blank=True)
    business_impact = models.TextField(blank=True)
    remediation = models.TextField(blank=True)

    ai_model = models.CharField(max_length=50, default='gpt-5.2')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('scan', 'name', 'cwe_id')
        ordering = ['-risk', '-cvss_score']

    def __str__(self):
        return f"AI: {self.name}"


class MonthlySummary(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='monthly_summaries')
    year_month = models.DateField(help_text='First day of month')
    total_scans = models.IntegerField(default=0)
    avg_risk_score = models.FloatField(default=0.0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)

    class Meta:
        unique_together = ('target', 'year_month')
        ordering = ['-year_month']

    def __str__(self):
        return f"{self.target.name} - {self.year_month.strftime('%Y-%m')}"


class OrganizationProfile(models.Model):
    """Organization info displayed on PDF reports. Supports multiple orgs."""
    name_th = models.CharField('ชื่อหน่วยงาน (ไทย)', max_length=300)
    name_en = models.CharField('ชื่อหน่วยงาน (อังกฤษ)', max_length=300, blank=True, default='')
    logo = models.ImageField('โลโก้', upload_to='org/', blank=True)
    address = models.TextField('ที่อยู่', blank=True, default='')
    phone = models.CharField('เบอร์โทร', max_length=50, blank=True, default='')
    email = models.EmailField('อีเมล', blank=True, default='')
    preparer_name = models.CharField('ชื่อผู้จัดทำรายงาน', max_length=200, blank=True, default='')
    preparer_title = models.CharField('ตำแหน่งผู้จัดทำ', max_length=200, blank=True, default='')
    approver_name = models.CharField('ชื่อผู้บริหาร', max_length=200, blank=True, default='')
    approver_title = models.CharField('ตำแหน่งผู้บริหาร', max_length=200, blank=True, default='')
    document_number_prefix = models.CharField('Prefix เลขที่เอกสาร', max_length=50, blank=True, default='VA-RPT-')
    is_default = models.BooleanField('หน่วยงานหลัก', default=False)

    class Meta:
        ordering = ['-is_default', 'name_th']
        verbose_name = 'Organization Profile'
        verbose_name_plural = 'Organization Profiles'

    def __str__(self):
        return self.name_th or 'Organization Profile'

    def set_as_default(self):
        """Mark this org as default and unmark all others."""
        OrganizationProfile.objects.exclude(pk=self.pk).update(is_default=False)
        self.is_default = True
        self.save(update_fields=['is_default'])

    @classmethod
    def load(cls, org_id=None):
        """Return org by id, or default, or first, or empty instance."""
        if org_id:
            obj = cls.objects.filter(pk=org_id).first()
            if obj:
                return obj
        obj = cls.objects.filter(is_default=True).first()
        if not obj:
            obj = cls.objects.first()
        if not obj:
            obj = cls(name_th='')
        return obj


class PentestAgreement(models.Model):
    """Pentest Scope of Work + NDA document for a single engagement."""

    # Document meta
    document_number = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Client (ผู้ว่าจ้าง)
    client_name_th = models.CharField(max_length=300)
    client_name_en = models.CharField(max_length=300, blank=True)
    client_address = models.TextField(blank=True)
    client_contact = models.CharField(max_length=200, blank=True)  # ผู้ติดต่อ
    client_signer_name = models.CharField(max_length=200, blank=True)
    client_signer_title = models.CharField(max_length=200, blank=True)

    # Tester / Service Provider (ผู้ให้บริการ) — pre-filled from OrganizationProfile
    tester_company_th = models.CharField(max_length=300, blank=True)
    tester_company_en = models.CharField(max_length=300, blank=True)
    tester_signer_name = models.CharField(max_length=200, blank=True)
    tester_signer_title = models.CharField(max_length=200, blank=True)

    # Scope
    test_type = models.CharField(max_length=200, blank=True,
                                 default='Black Box Penetration Testing (Zero-knowledge)')
    target_systems = models.TextField(blank=True)       # ระบบที่ทดสอบ (one per line)
    scope_description = models.TextField(blank=True)    # รายละเอียดขอบเขต / เหตุผลช่วงเวลา
    out_of_scope = models.TextField(blank=True)          # นอกขอบเขต
    methodology = models.TextField(blank=True)           # วิธีการทดสอบ (one per line)
    rules_of_engagement = models.TextField(blank=True)  # ข้อตกลงและเงื่อนไขการทดสอบ (one per line)
    deliverables = models.TextField(blank=True)          # ผลผลิตที่ต้องส่งมอบ (one per line)
    team_members = models.TextField(blank=True)          # ทีมงานผู้ทดสอบ

    # Test Periods — list of {date_from, time_from, date_to, time_to}
    test_periods = models.JSONField(default=list, blank=True)
    # Legacy single-period fields (kept for backward compatibility)
    test_start_date = models.DateField(null=True, blank=True)
    test_end_date = models.DateField(null=True, blank=True)
    test_hours = models.CharField(max_length=100, blank=True, default='')

    # Organization used for PDF header/logo
    org_id = models.IntegerField('หน่วยงาน (สำหรับ PDF)', null=True, blank=True)

    # NDA
    nda_duration_years = models.IntegerField(default=3)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.document_number} - {self.client_name_th}"


class TeamCertificate(models.Model):
    """ใบประกาศนียบัตร / คุณวุฒิของทีมงานผู้ทดสอบ"""
    person_name = models.CharField('ชื่อ-นามสกุล', max_length=200)
    course_name  = models.CharField('ชื่อหลักสูตร', max_length=300)
    issuer       = models.CharField('หน่วยงานที่ให้', max_length=300, blank=True)
    file         = models.FileField('ไฟล์ใบประกาศ', upload_to='certificates/')
    uploaded_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['person_name', 'course_name']

    def __str__(self):
        return f"{self.person_name} — {self.course_name}"

    @property
    def file_ext(self):
        return self.file.name.rsplit('.', 1)[-1].lower() if self.file else ''

    @property
    def is_image(self):
        return self.file_ext in ('jpg', 'jpeg', 'png')

    @property
    def is_pdf(self):
        return self.file_ext == 'pdf'
