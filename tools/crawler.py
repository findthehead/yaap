#!/usr/bin/env python3
import argparse
import html
import os
import queue
import re
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


class LinkFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()
        self.forms = []
        self._in_form = False
        self._form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'href' in attrs:
            self.links.add(attrs['href'])
        elif tag == 'form':
            self._in_form = True
            self._form = {
                'action': attrs.get('action', ''),
                'method': (attrs.get('method', 'get') or 'get').lower(),
                'inputs': []
            }
        elif self._in_form and tag in ('input', 'textarea', 'select'):
            name = attrs.get('name')
            ipt_type = attrs.get('type', 'text').lower()
            if name:
                self._form['inputs'].append({'name': name, 'type': ipt_type})

    def handle_endtag(self, tag):
        if tag == 'form' and self._in_form:
            self.forms.append(self._form)
            self._in_form = False
            self._form = None


def fetch(url: str, ua: str = 'Mozilla/5.0 (Pentest Bot)') -> str:
    req = Request(url, headers={'User-Agent': ua})
    with urlopen(req, timeout=15) as resp:
        ctype = resp.headers.get('Content-Type', '')
        if 'text' not in ctype and 'html' not in ctype:
            return ''
        data = resp.read()
        try:
            return data.decode('utf-8', errors='ignore')
        except Exception:
            return data.decode('latin-1', errors='ignore')


def crawl(origin: str, max_pages: int = 30, same_host: bool = True):
    origin_parsed = urlparse(origin if '://' in origin else 'http://' + origin)
    base = f"{origin_parsed.scheme}://{origin_parsed.netloc}"
    seen = set()
    q = queue.Queue()
    q.put(origin)
    results = {
        'visited': [],
        'links': set(),
        'forms': [],
    }
    count = 0
    while not q.empty() and count < max_pages:
        url = q.get()
        if url in seen:
            continue
        seen.add(url)
        count += 1
        try:
            html_text = fetch(url)
        except Exception:
            continue
        parser = LinkFormParser()
        try:
            parser.feed(html_text)
        except Exception:
            pass
        results['visited'].append(url)
        for href in parser.links:
            new_url = urljoin(url, href)
            pu = urlparse(new_url)
            if same_host and pu.netloc and pu.netloc != origin_parsed.netloc:
                continue
            if pu.scheme in ('http', 'https'):
                results['links'].add(new_url)
                if new_url not in seen:
                    q.put(new_url)
        # Normalize form actions
        for f in parser.forms:
            action = f.get('action', '')
            abs_action = urljoin(url, action) if action else url
            f['action'] = abs_action
            results['forms'].append(f)
    return results


def main():
    ap = argparse.ArgumentParser(description='Lightweight crawler + form collector')
    ap.add_argument('--url', required=True, help='Origin URL (scheme optional)')
    ap.add_argument('--max-pages', type=int, default=30)
    ap.add_argument('--out', default='', help='Optional output file path (txt)')
    args = ap.parse_args()

    res = crawl(args.url, max_pages=args.max_pages)
    lines = []
    lines.append('# Visited pages:')
    for u in res['visited']:
        lines.append(u)
    lines.append('\n# Discovered links:')
    for u in sorted(res['links']):
        lines.append(u)
    lines.append('\n# Forms: action method fields')
    for f in res['forms']:
        fields = ','.join(i['name'] for i in f.get('inputs', []) if i.get('name'))
        lines.append(f"{f.get('action')} {f.get('method')} {fields}")
    text = '\n'.join(lines)
    if args.out:
        try:
            os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
            with open(args.out, 'w', encoding='utf-8') as fp:
                fp.write(text)
        except Exception:
            pass
    print(text)


if __name__ == '__main__':
    main()

