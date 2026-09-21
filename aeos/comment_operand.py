"""A closed, policy-bound comment operand. No prose interpretation or route creation.

The independent judge binds an already-reviewed lowering, including its ceiling.
GitHub facts may disprove that binding; candidate bytes can never supply it.
The collector uses the existing workflow's injected read-only API, not candidate code.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re

SCHEMA = 'aeos-comment-operand/v1'
MAX_COMMENTS = 1000
MAX_PAGES = 10
MAX_AGE_SECONDS = 300
REF = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[1-9][0-9]*\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
ROW_KEYS = ('id', 'body_sha256', 'author_login', 'author_type', 'updated_at')
AUTHORITY_KEYS = {'schema', 'state', 'repository', 'issue', 'not_after', 'path_envelope'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def body_digest(body):
    return hashlib.sha256(body.encode()).hexdigest()


def authority_body(block):
    return '```standing-authority\n' + json.dumps(block) + '\n```\n'


def validate(operand, parser):
    """Validate the closed reviewed lowering, including its same-or-narrower claim.

    The generation binds every source, scope and authority axis. This is an operand
    version, not a new execution-generation store or an admission side effect.
    """
    if (not isinstance(operand, dict) or set(operand) != {
            'schema', 'programme', 'scope', 'generation', 'sources', 'authority', 'ceiling'}
            or operand['schema'] != SCHEMA or operand['scope'] != 'repository-code'
            or not isinstance(operand['programme'], str) or not REF.fullmatch(operand['programme'])):
        raise ValueError('comment operand shape')
    unsigned = {k: v for k, v in operand.items() if k != 'generation'}
    if operand['generation'] != operand['programme'] + '@sha256:' + digest(unsigned):
        raise ValueError('comment operand generation')
    sources = operand['sources']
    if (not isinstance(sources, list) or len(sources) != 3
            or [s.get('role') for s in sources if isinstance(s, dict)] !=
            ['ratification', 'admission', 'registration']):
        raise ValueError('comment operand lineage')
    identities = []
    for source in sources:
        if (set(source) != {'role', 'ref', 'comment_id', 'issue_body_sha256',
                           'comment_body_sha256', 'frontier_sha256'}
                or not isinstance(source['ref'], str) or not REF.fullmatch(source['ref'])
                or type(source['comment_id']) is not int or source['comment_id'] <= 0
                or any(not isinstance(source[k], str) or not SHA.fullmatch(source[k])
                       for k in ('issue_body_sha256', 'comment_body_sha256', 'frontier_sha256'))):
            raise ValueError('comment operand source')
        identities.append((source['ref'], source['comment_id']))
    if len(set(identities)) != 3 or sources[0]['ref'] != operand['programme']:
        raise ValueError('comment operand source identity')
    for key in ('authority', 'ceiling'):
        block = operand[key]
        if not isinstance(block, dict) or set(block) != AUTHORITY_KEYS or parser(authority_body(block)) is None:
            raise ValueError('comment operand authority shape')
        if f"{block['repository']}#{block['issue']}" != operand['programme'] or block['state'] != 'ACTIVE':
            raise ValueError('comment operand programme')
    authority, ceiling = operand['authority'], operand['ceiling']
    parse_time = lambda s: datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))
    if parse_time(authority['not_after']) > parse_time(ceiling['not_after']):
        raise ValueError('comment operand expiry widened')
    # Exact files only on this new operand. No inferred directories or root expansion.
    if (any(p.endswith('/') for p in ceiling['path_envelope'] + authority['path_envelope'])
            or len(set(authority['path_envelope'])) != len(authority['path_envelope'])
            or not set(authority['path_envelope']) <= set(ceiling['path_envelope'])):
        raise ValueError('comment operand scope widened')


def resolve(operand, evidence, programme, policy, parser, now):
    """Return only the normalized parser input, or None (never an admission effect)."""
    try:
        validate(operand, parser)
        if programme['ref'] != operand['programme']:
            return None
        # A second body source, even a malformed one, is ambiguous. Never fallback around it.
        if '```standing-authority' in programme['body']:
            return None
        facts = evidence['comment_sources']
        observed = facts['observed_at']
        if type(observed) not in (int, float) or not 0 <= now - observed <= MAX_AGE_SECONDS:
            return None
        rows = facts['sources']
        if not isinstance(rows, list) or len(rows) != len(operand['sources']):
            return None
        for binding, fact in zip(operand['sources'], rows):
            if fact['ref'] != binding['ref'] or fact['state'] != 'open':
                return None
            if (fact['author_login'] not in policy.operator_principals or fact['author_type'] != 'User'
                    or not isinstance(fact['editors'], list) or len(fact['editors']) > 100
                    or any(e not in policy.operator_principals for e in fact['editors'])):
                return None
            if body_digest(fact['body']) != binding['issue_body_sha256']:
                return None
            if binding['role'] == 'ratification' and fact['body'] != programme['body']:
                return None
            comments = fact['comments']
            if (not isinstance(comments, list) or type(fact['comments_total']) is not int
                    or len(comments) != fact['comments_total'] or not 1 <= len(comments) <= MAX_COMMENTS):
                return None
            ids = [c['id'] for c in comments]
            if (any(type(i) is not int or i <= 0 for i in ids)
                    or ids != sorted(set(ids)) or digest(comments) != binding['frontier_sha256']):
                return None
            selected = fact['selected']
            if selected['id'] != binding['comment_id']:
                return None
            matches = [c for c in comments if c['id'] == selected['id']]
            if matches != [{k: selected[k] for k in ROW_KEYS}]:
                return None
            principal = (selected['author_login'], selected['author_type'])
            operator = principal[0] in policy.operator_principals and principal[1] == 'User'
            if not operator and (binding['role'] == 'ratification' or principal not in policy.machine_principals):
                return None
            # Edited/deleted provenance is not an unedited authenticated comment.
            if (selected['editors'] != [] or not isinstance(selected['created_at'], str)
                    or selected['created_at'] != selected['updated_at']):
                return None
            if (body_digest(selected['body']) != binding['comment_body_sha256']
                    or selected['body_sha256'] != binding['comment_body_sha256']):
                return None
        return authority_body(operand['authority'])
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return None


QUERY = '''query($o:String!,$n:String!,$i:Int!,$cursor:String){repository(owner:$o,name:$n){issue(number:$i){
id number repository{nameWithOwner} body state author{login __typename}
userContentEdits(first:100){totalCount nodes{editor{login __typename}}}
comments(first:100,after:$cursor){totalCount pageInfo{hasNextPage endCursor}
nodes{databaseId body createdAt updatedAt isMinimized author{login __typename}
userContentEdits(first:1){totalCount}}}}}}'''


def collect(operand, api, observed_at):
    """Project authenticated API facts only; never read an operand from the candidate.

    Each source is read twice. Incomplete pagination, deleted edit records, API errors,
    and movement during collection are unavailable, not an empty history.
    """
    def read(binding):
        repo, number = binding['ref'].split('#')
        owner, name = repo.split('/')
        cursor, header, total = None, None, None
        cursors, nodes, ids = set(), [], set()
        while True:
            if len(cursors) >= MAX_PAGES:
                raise ValueError('source page budget exceeded')
            args = ('-f', 'cursor=' + cursor) if cursor is not None else ()
            response = api('graphql', '-f', 'query=' + QUERY, '-f', 'o=' + owner,
                           '-f', 'n=' + name, '-F', 'i=' + number, *args)
            if not isinstance(response, dict) or response.get('errors'):
                raise ValueError('source unavailable')
            issue = response['data']['repository']['issue']
            if (issue['repository']['nameWithOwner'] != repo or type(issue['number']) is not int
                    or issue['number'] != int(number) or not isinstance(issue['id'], str) or not issue['id']):
                raise ValueError('foreign source')
            current = {k: v for k, v in issue.items() if k != 'comments'}
            connection = issue['comments']
            count = connection['totalCount']
            if type(count) is not int or not 1 <= count <= MAX_COMMENTS:
                raise ValueError('source frontier bound')
            if header is not None and (current != header or count != total):
                raise ValueError('source changed between pages')
            header, total = current, count
            page, info = connection['nodes'], connection['pageInfo']
            if (not isinstance(page, list) or not 1 <= len(page) <= 100
                    or type(info['hasNextPage']) is not bool
                    or not isinstance(info['endCursor'], str) or not info['endCursor']
                    or info['endCursor'] in cursors):
                raise ValueError('source page incomplete')
            for node in page:
                ident = node['databaseId']
                if (type(ident) is not int or ident <= 0 or ident in ids
                        or (nodes and ident <= nodes[-1]['databaseId']) or node['isMinimized'] is not False):
                    raise ValueError('source comment hidden or ambiguous')
                ids.add(ident)
                nodes.append(node)
            if len(nodes) > total or info['hasNextPage'] != (len(nodes) < total):
                raise ValueError('source frontier incomplete')
            cursors.add(info['endCursor'])
            if not info['hasNextPage']:
                break
            cursor = info['endCursor']
        edits = issue['userContentEdits']
        if (type(edits['totalCount']) is not int or edits['totalCount'] != len(edits['nodes'])
                or len(edits['nodes']) > 100
                or any(n['editor']['__typename'] != 'User' for n in edits['nodes'])):
            raise ValueError('source edit history incomplete')
        comments, selected = [], None
        for node in nodes:
            row = dict(id=node['databaseId'], body_sha256=body_digest(node['body']),
                       author_login=node['author']['login'], author_type=node['author']['__typename'],
                       updated_at=node['updatedAt'])
            comments.append(row)
            if row['id'] == binding['comment_id']:
                if selected is not None:
                    raise ValueError('duplicate selected source')
                if type(node['userContentEdits']['totalCount']) is not int or node['userContentEdits']['totalCount'] != 0:
                    raise ValueError('selected source edited')
                selected = dict(row, body=node['body'], created_at=node['createdAt'], editors=[])
        if selected is None:
            raise ValueError('selected source absent')
        fact = dict(ref=binding['ref'], state=issue['state'].lower(), body=issue['body'],
                    author_login=issue['author']['login'], author_type=issue['author']['__typename'],
                    editors=[n['editor']['login'] for n in edits['nodes']], comments=comments,
                    comments_total=total, selected=selected)
        # Compare the immutable Issue identity too, without changing the v1 operand.
        return fact, issue['id']

    try:
        first = [read(s) for s in operand['sources']]
        second = [read(s) for s in operand['sources']]
        if first != second:
            raise ValueError('source moved')
        return dict(observed_at=observed_at, sources=[fact for fact, _identity in second])
    except (KeyError, TypeError, ValueError, AttributeError):
        return {'unavailable': 'COMMENT_SOURCE_UNAVAILABLE'}
