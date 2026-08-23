#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPEC.md -> 左ナビ付き HTML。SPEC.md で実際に使っている記法だけを扱う。"""
import re, html, sys, io

SRC = sys.argv[1]
DST = sys.argv[2]

raw = io.open(SRC, encoding='utf-8').read().split('\n')

ANCHOR_RE = re.compile(r'<a id="([A-Za-z0-9\-]+)"></a>')
HEAD_RE   = re.compile(r'^(#{1,4})\s+(.*)$')
TBLSEP_RE = re.compile(r'^\|[\s:\-|]+\|$')


def inline(s):
    anchors, codes = [], []

    def keep_anchor(m):
        anchors.append(m.group(0))
        return '\x00A%d\x00' % (len(anchors) - 1)

    def keep_code(m):
        codes.append(m.group(1))
        return '\x00C%d\x00' % (len(codes) - 1)

    s = ANCHOR_RE.sub(keep_anchor, s)
    s = re.sub(r'`([^`]+)`', keep_code, s)
    s = html.escape(s, quote=False)
    s = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', s)
    s = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', s)
    s = re.sub(r'\x00C(\d+)\x00',
               lambda m: '<code>' + html.escape(codes[int(m.group(1))], quote=False) + '</code>', s)
    s = re.sub(r'\x00A(\d+)\x00', lambda m: anchors[int(m.group(1))], s)
    return s.replace('\\|', '|')


def cells(row):
    row = row.strip()
    if row.startswith('|'):
        row = row[1:]
    if row.endswith('|'):
        row = row[:-1]
    return [c.strip() for c in re.split(r'(?<!\\)\|', row)]


out = []
nav = []          # (kind, id, label)
pending_id = None
i = 0
n = len(raw)
skipping_toc = False

while i < n:
    line = raw[i]

    # 目次の節は左ナビが置き換えるので HTML からは省く
    if line.startswith('## 目次'):
        skipping_toc = True
        i += 1
        continue
    if skipping_toc:
        if line.startswith('# 第 I 部'):
            skipping_toc = False
        else:
            i += 1
            continue

    # 単独行のアンカー
    m = ANCHOR_RE.fullmatch(line.strip())
    if m:
        pending_id = m.group(1)
        i += 1
        continue

    # コードブロック
    if line.startswith('```'):
        buf = []
        i += 1
        while i < n and not raw[i].startswith('```'):
            buf.append(html.escape(raw[i], quote=False))
            i += 1
        i += 1
        out.append('<div class="codewrap"><pre><code>%s</code></pre></div>' % '\n'.join(buf))
        continue

    # 見出し
    m = HEAD_RE.match(line)
    if m:
        level = len(m.group(1))
        text = inline(m.group(2))
        attr = ''
        if pending_id:
            attr = ' id="%s"' % pending_id
        if level == 1:
            if raw[i].startswith('# 第') or raw[i].startswith('# 付録'):
                slug = 'part-%d' % len([x for x in nav if x[0] == 'part'])
                nav.append(('part', slug, m.group(2)))
                out.append('<h2 class="parthead" id="%s">%s</h2>' % (slug, text))
            else:
                out.append('<h1%s>%s</h1>' % (attr, text))
        elif level == 2:
            if pending_id and (pending_id.startswith('ch') or pending_id.startswith('appendix')):
                nav.append(('chapter', pending_id, m.group(2)))
            out.append('<h3 class="chaphead"%s>%s</h3>' % (attr, text))
        elif level == 3:
            out.append('<h4%s>%s</h4>' % (attr, text))
        else:
            out.append('<h5%s>%s</h5>' % (attr, text))
        pending_id = None
        i += 1
        continue

    # 表
    if line.startswith('|') and i + 1 < n and TBLSEP_RE.match(raw[i + 1].strip()):
        head = cells(line)
        i += 2
        body = []
        while i < n and raw[i].strip().startswith('|'):
            body.append(cells(raw[i]))
            i += 1
        t = ['<div class="tablewrap"><table><thead><tr>']
        t += ['<th>%s</th>' % inline(c) for c in head]
        t.append('</tr></thead><tbody>')
        for r in body:
            t.append('<tr>' + ''.join('<td>%s</td>' % inline(c) for c in r) + '</tr>')
        t.append('</tbody></table></div>')
        out.append(''.join(t))
        continue

    # 引用
    if line.startswith('> '):
        buf = []
        while i < n and (raw[i].startswith('> ') or raw[i].strip() == '>'):
            buf.append(raw[i][2:] if len(raw[i]) > 2 else '')
            i += 1
        paras, cur = [], []
        for b in buf:
            if b.strip() == '':
                if cur:
                    paras.append(' '.join(cur))
                    cur = []
            else:
                cur.append(b.strip())
        if cur:
            paras.append(' '.join(cur))
        out.append('<blockquote>' + ''.join('<p>%s</p>' % inline(p) for p in paras) + '</blockquote>')
        continue

    # 箇条書き / 番号付き
    if re.match(r'^\s*[-*]\s+', line) or re.match(r'^\s*\d+\.\s+', line):
        ordered = bool(re.match(r'^\s*\d+\.\s+', line))
        items = []
        while i < n and (re.match(r'^\s*[-*]\s+', raw[i]) or re.match(r'^\s*\d+\.\s+', raw[i])
                         or (items and raw[i].startswith('  ') and raw[i].strip())):
            if re.match(r'^\s*[-*]\s+', raw[i]) or re.match(r'^\s*\d+\.\s+', raw[i]):
                items.append(re.sub(r'^\s*(?:[-*]|\d+\.)\s+', '', raw[i]))
            else:
                items[-1] += ' ' + raw[i].strip()
            i += 1
        tag = 'ol' if ordered else 'ul'
        out.append('<%s>%s</%s>' % (tag, ''.join('<li>%s</li>' % inline(x) for x in items), tag))
        continue

    # 水平線
    if line.strip() == '---':
        out.append('<hr>')
        i += 1
        continue

    # 空行
    if line.strip() == '':
        i += 1
        continue

    # 段落
    buf = []
    while i < n and raw[i].strip() != '' and not raw[i].startswith('#') \
            and not raw[i].startswith('|') and not raw[i].startswith('```') \
            and not raw[i].startswith('> ') and raw[i].strip() != '---' \
            and not re.match(r'^\s*[-*]\s+', raw[i]) and not re.match(r'^\s*\d+\.\s+', raw[i]) \
            and not ANCHOR_RE.fullmatch(raw[i].strip()):
        buf.append(raw[i].strip())
        i += 1
    if buf:
        out.append('<p>%s</p>' % inline(' '.join(buf)))

# ---- 左ナビの組み立て ----
navhtml = []
open_group = False
for kind, slug, label in nav:
    if kind == 'part':
        if open_group:
            navhtml.append('</ul></li>')
        navhtml.append('<li class="navpart"><a class="navpartlink" href="#%s">%s</a><ul>'
                       % (slug, html.escape(label, quote=False)))
        open_group = True
    else:
        num = ''
        mm = re.match(r'^第\s*(\d+)\s*章', label)
        if mm:
            num = mm.group(1)
            rest = re.sub(r'^第\s*\d+\s*章\s*', '', label)
        else:
            mm2 = re.match(r'^付録\s*([A-C])', label)
            num = mm2.group(1) if mm2 else ''
            rest = re.sub(r'^付録\s*[A-C]\s*', '', label)
        navhtml.append('<li><a href="#%s" data-target="%s"><span class="num">%s</span>'
                       '<span class="lbl">%s</span></a></li>'
                       % (slug, slug, num, html.escape(rest, quote=False)))
if open_group:
    navhtml.append('</ul></li>')

body = '\n'.join(out)
navigation = '\n'.join(navhtml)

tpl = io.open(sys.argv[3], encoding='utf-8').read()
page = tpl.replace('<!--NAV-->', navigation).replace('<!--BODY-->', body)
io.open(DST, 'w', encoding='utf-8').write(page)
print('chapters in nav:', len([x for x in nav if x[0] == 'chapter']))
print('parts in nav   :', len([x for x in nav if x[0] == 'part']))
print('output bytes   :', len(page))
