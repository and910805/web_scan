from django.core.management.base import BaseCommand

from scans.tasks import run_scheduled_scans


class Command(BaseCommand):
    help = "Enqueue all due scheduled scans."

    def handle(self, *args, **options):
        result = run_scheduled_scans.delay()
        self.stdout.write(self.style.SUCCESS(f"Triggered scheduled scan task {result.id}"))
