import os
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from scanner.models import Scan, PentestAgreement
from .pdf_generator import generate_pdf, generate_owasp_coverage_pdf
from .excel_exporter import generate_excel


def export_pdf(request, scan_id):
    scan = get_object_or_404(Scan.objects.select_related('target'), id=scan_id)
    org_id = request.GET.get('org_id')
    return generate_pdf(scan, org_id=org_id)


def export_excel(request, scan_id):
    scan = get_object_or_404(Scan.objects.select_related('target'), id=scan_id)
    return generate_excel(scan)


def export_owasp_pdf(request):
    org_id = request.GET.get('org_id')
    return generate_owasp_coverage_pdf(org_id=org_id)


def export_agreement_pdf(request, pk):
    """Export agreement as PDF via LibreOffice (docxtpl path)."""
    from django.http import HttpResponse
    agreement = get_object_or_404(PentestAgreement, pk=pk)
    org_id = request.GET.get('org_id') or agreement.org_id
    from .docx_generator import generate_agreement_pdf_docx
    try:
        pdf_bytes = generate_agreement_pdf_docx(agreement, org_id=org_id)
        safe = (agreement.document_number or f'agreement-{pk}').replace('/', '-')
        resp = HttpResponse(pdf_bytes, content_type='application/pdf')
        resp['Content-Disposition'] = f'inline; filename="{safe}.pdf"'
        return resp
    except Exception as exc:
        import logging
        logging.getLogger(__name__).exception('Agreement PDF failed: %s', exc)
        messages.error(request, f'สร้าง PDF ไม่สำเร็จ: {exc}')
        return redirect(request.META.get('HTTP_REFERER', '/'))


def download_agreement_template(request):
    """Download the current agreement_template.docx for editing."""
    from django.http import HttpResponse
    from .docx_generator import TEMPLATE_PATH, build_template
    if not os.path.exists(TEMPLATE_PATH):
        build_template()
    with open(TEMPLATE_PATH, 'rb') as f:
        data = f.read()
    resp = HttpResponse(
        data,
        content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    )
    resp['Content-Disposition'] = 'attachment; filename="agreement_template.docx"'
    return resp


def reset_agreement_template(request):
    """Regenerate the default template (POST only)."""
    from django.shortcuts import redirect
    from django.contrib import messages
    from .docx_generator import build_template
    if request.method == 'POST':
        build_template()
        messages.success(request, 'รีเซ็ต template กลับเป็นค่าเริ่มต้นแล้ว')
    return redirect('/agreements/')


def export_agreement_docx(request, pk):
    """Export agreement as .docx download."""
    from django.http import HttpResponse
    agreement = get_object_or_404(PentestAgreement, pk=pk)
    org_id = request.GET.get('org_id') or agreement.org_id
    from .docx_generator import generate_agreement_docx
    docx_bytes = generate_agreement_docx(agreement, org_id=org_id)
    safe = (agreement.document_number or f'agreement-{pk}').replace('/', '-')
    resp = HttpResponse(
        docx_bytes,
        content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    )
    resp['Content-Disposition'] = f'attachment; filename="{safe}.docx"'
    return resp


def combined_report(request):
    """Generate combined multi-scan PDF or Excel from report builder form."""
    if request.method != 'POST':
        return redirect('dashboard-report-builder')

    scan_ids = request.POST.getlist('scan_ids')
    report_format = request.POST.get('report_format', 'pdf')
    report_title = request.POST.get('report_title', '').strip()
    org_id = request.POST.get('org_id')

    if not scan_ids:
        messages.error(request, 'กรุณาเลือกอย่างน้อย 1 scan')
        return redirect('dashboard-report-builder')

    if report_format == 'excel':
        from .pdf_generator import generate_combined_excel
        return generate_combined_excel(scan_ids)
    else:
        from .pdf_generator import generate_combined_pdf
        return generate_combined_pdf(scan_ids, report_title, org_id=org_id)
