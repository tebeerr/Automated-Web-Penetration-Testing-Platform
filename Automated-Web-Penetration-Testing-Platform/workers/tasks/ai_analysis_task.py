from workers.celery_app import celery_app


@celery_app.task(name="ai.analyze", bind=True, soft_time_limit=600)
def run_ai_analysis(self, scan_id: str) -> str:
    """Standalone AI analysis pass over an existing scan's findings.

    Implementation lives in packages/ai-agent. Wire AIOrchestrator once available.
    """
    return scan_id
