# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Django imports
from django.core.cache import cache
from django.core.management import BaseCommand


class Command(BaseCommand):
    help = "Clear an explicitly named cache key while preserving shared Redis state"

    def add_arguments(self, parser):
        # Positional argument
        parser.add_argument("--key", type=str, nargs="?", help="Key to clear cache")

    def handle(self, *args, **options):
        try:
            if options["key"]:
                cache.delete(options["key"])
                self.stdout.write(self.style.SUCCESS(f"Cache Cleared for key: {options['key']}"))
                return

            self.stdout.write(self.style.WARNING("No cache key specified; shared Redis state preserved"))
            return
        except Exception:
            # Another ClientError occurred
            self.stdout.write(self.style.ERROR("Failed to clear cache"))
            return
