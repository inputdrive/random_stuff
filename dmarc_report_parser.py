#!/usr/bin/env python3
# Simple DMARC aggregate report parser.
# Reads *.xml and *.xml.gz in the current directory and prints pass/fail rates.
import glob
import gzip
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone


def clean_text(text, fallback):
    flattened = ' '.join((text or '').split())
    return flattened or fallback


def strip_namespaces(elem):
    for node in elem.iter():
        if isinstance(node.tag, str) and node.tag.startswith('{'):
            node.tag = node.tag.split('}', 1)[1]


def parse_count(text):
    if text is None:
        return None
    try:
        value = int(text.strip())
    except ValueError:
        return None
    if value < 0:
        return None
    return value


def format_day(text):
    raw = (text or '').strip()
    if not raw:
        return '?'
    try:
        stamp = int(raw)
    except ValueError:
        return raw
    return datetime.fromtimestamp(stamp, timezone.utc).strftime('%Y-%m-%d')


def load_tree(path):
    if path.lower().endswith('.gz'):
        with gzip.open(path, 'rb') as handle:
            return ET.parse(handle)
    return ET.parse(path)


def parse_dmarc_report(path):
    root = load_tree(path).getroot()
    strip_namespaces(root)
    records = []
    for record in root.findall('.//record'):
        count = parse_count(record.findtext('row/count'))
        if count is None:
            continue
        # policy_evaluated is the aligned DMARC verdict.
        # auth_results/dkim is a parent element and is not that verdict.
        dkim = (record.findtext('row/policy_evaluated/dkim') or '').strip().lower()
        spf = (record.findtext('row/policy_evaluated/spf') or '').strip().lower()
        records.append({
            'ip': clean_text(record.findtext('row/source_ip'), '(no ip)'),
            'count': count,
            'dkim': dkim,
            'spf': spf,
        })
    return {
        'org': clean_text(root.findtext('report_metadata/org_name'), '(unknown reporter)'),
        'domain': clean_text(root.findtext('policy_published/domain'), '(unknown domain)'),
        'begin': format_day(root.findtext('report_metadata/date_range/begin')),
        'end': format_day(root.findtext('report_metadata/date_range/end')),
        'records': records,
    }


def passed(record):
    return record['dkim'] == 'pass' or record['spf'] == 'pass'


def percent(part, total):
    if total == 0:
        return 0
    return 100 * part // total


def report_lines(report):
    records = report['records']
    total = sum(record['count'] for record in records)
    pass_count = sum(record['count'] for record in records if passed(record))
    fail_count = total - pass_count
    lines = [
        '',
        f"{report['org']}  {report['domain']}  {report['begin']} to {report['end']}",
        f"  {total} messages",
        f"  Pass: {pass_count} ({percent(pass_count, total)}%)",
        f"  Fail: {fail_count} ({percent(fail_count, total)}%)",
    ]
    by_ip = defaultdict(lambda: {'count': 0, 'passed': 0})
    for record in records:
        bucket = by_ip[record['ip']]
        bucket['count'] += record['count']
        if passed(record):
            bucket['passed'] += record['count']
    ranked = sorted(by_ip.items(), key=lambda item: item[1]['count'], reverse=True)
    for ip, bucket in ranked[:5]:
        failed = bucket['count'] - bucket['passed']
        lines.append(f"  {ip}  {bucket['count']}  pass={bucket['passed']} fail={failed}")
    return lines


def report_paths():
    paths = glob.glob('*.xml') + glob.glob('*.xml.gz')
    return sorted(paths, key=str.lower)


def main():
    paths = report_paths()
    if not paths:
        print('No *.xml or *.xml.gz reports in the current directory.', file=sys.stderr)
        return 0
    exit_code = 0
    for path in paths:
        try:
            print('\n'.join(report_lines(parse_dmarc_report(path))))
        except (ET.ParseError, OSError) as exc:
            print(f'{path}: {exc}', file=sys.stderr)
            exit_code = 1
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
