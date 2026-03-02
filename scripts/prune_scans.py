#!/Users/hrishikesh/Desktop/github_projects/vulnreach-parent/vuln-reachability-sample/labs/python_vuln_app/.venv/bin/python3
"""prune_scans.py — keep only the N most recent scans in the database.

Usage:
    python3 scripts/prune_scans.py          # keeps 10 (default)
    python3 scripts/prune_scans.py --keep 5
    python3 scripts/prune_scans.py --dry-run
"""

import argparse
import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv optional — set DATABASE_URL in environment directly

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    print("ERROR: psycopg2 not installed — run: pip install psycopg2-binary")
    sys.exit(1)


def prune(keep: int = 10, dry_run: bool = False) -> None:
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        print("ERROR: DATABASE_URL environment variable is not set")
        sys.exit(1)

    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # List all scans ordered newest first
            cur.execute("SELECT id, status, created_at FROM scans ORDER BY created_at DESC")
            all_scans = cur.fetchall()

        total = len(all_scans)
        to_delete = all_scans[keep:]  # everything beyond the most recent N

        print(f"Total scans : {total}")
        print(f"Keeping     : {min(keep, total)}")
        print(f"Deleting    : {len(to_delete)}")

        if not to_delete:
            print("Nothing to prune.")
            return

        print()
        for row in to_delete:
            print(f"  DELETE  {row['id']}  [{row['status']}]  {row['created_at']}")

        if dry_run:
            print("\nDry-run — no changes made.")
            return

        ids = [row["id"] for row in to_delete]
        with conn.cursor() as cur:
            # ON DELETE CASCADE handles all child rows automatically
            cur.execute("DELETE FROM scans WHERE id = ANY(%s::uuid[])", (ids,))
            deleted = cur.rowcount
        conn.commit()
        print(f"\nDeleted {deleted} scan(s).")

    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prune old scans from the VulnReach database")
    parser.add_argument("--keep",    type=int, default=10, help="Number of recent scans to keep (default: 10)")
    parser.add_argument("--dry-run", action="store_true",  help="Preview what would be deleted without making changes")
    args = parser.parse_args()

    prune(keep=args.keep, dry_run=args.dry_run)
