from workers.celery_app import celery_app


@celery_app.task(name="report.generate", bind=True, soft_time_limit=300)
def generate_report(self, scan_id: str) -> str:
    """Standalone PDF generation. Wire PDFReportBuilder when packages/report-gen lands."""
    return scan_id
