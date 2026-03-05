from django.urls import path
from . import views

urlpatterns = [
    path('pdf/<uuid:scan_id>/', views.export_pdf, name='reports-pdf'),
    path('excel/<uuid:scan_id>/', views.export_excel, name='reports-excel'),
    path('owasp-pdf/', views.export_owasp_pdf, name='reports-owasp-pdf'),
    path('combined/', views.combined_report, name='reports-combined-pdf'),
    path('agreement/<int:pk>/pdf/',  views.export_agreement_pdf,  name='reports-agreement-pdf'),
    path('agreement/<int:pk>/docx/',   views.export_agreement_docx,        name='reports-agreement-docx'),
    path('agreement/template/download/', views.download_agreement_template, name='reports-agreement-template-download'),
    path('agreement/template/reset/',    views.reset_agreement_template,    name='reports-agreement-template-reset'),
]
