"""The comment operand is trusted policy data, never a candidate grant."""
import copy
import datetime
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import derivation_policy as dp
import comment_operand as co


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


class CommentOperandTests(unittest.TestCase):
    def setUp(self):
        self.repo = 'example/project'
        self.ref = self.repo + '#7'
        self.now = datetime.datetime(2026, 9, 21, tzinfo=datetime.timezone.utc).timestamp()
        self.authority = dict(schema='standing-authority/v2', state='ACTIVE',
                              repository=self.repo, issue=7,
                              not_after='2026-09-22T00:00:00Z',
                              path_envelope=['scripts/agent_relay/models.py'])
        self.facts = []
        bindings = []
        for role, number in [('ratification', 7), ('admission', 8), ('registration', 9)]:
            body = 'Exact reviewed ' + role + ' source; not an executable grant.'
            sha = hashlib.sha256(body.encode()).hexdigest()
            row = dict(id=number * 100, body_sha256=sha, author_login='operator',
                       author_type='User', updated_at='2026-09-20T00:00:00Z')
            fact = dict(ref=self.repo + '#' + str(number), state='open', body='Programme',
                        author_login='operator', author_type='User', editors=[],
                        comments=[row], comments_total=1,
                        selected=dict(row, body=body, editors=[],
                                      created_at='2026-09-20T00:00:00Z'))
            self.facts.append(fact)
            bindings.append(dict(role=role, ref=fact['ref'], comment_id=row['id'],
                                 issue_body_sha256=hashlib.sha256(b'Programme').hexdigest(),
                                 comment_body_sha256=sha, frontier_sha256=digest([row])))
        self.operand = dict(schema='aeos-comment-operand/v1', programme=self.ref,
                            scope='repository-code', authority=self.authority,
                            ceiling=copy.deepcopy(self.authority), sources=bindings)
        self.operand['generation'] = self.ref + '@sha256:' + digest(self.operand)
        doc = json.loads((Path(__file__).resolve().parents[1] / dp.POLICY_FILE).read_text())
        doc['target_repository'] = self.repo
        doc['machine_route'] = dict(machine_principals=[dict(login='machine[bot]', type='Bot')],
                                    operator_principals=['operator'])
        self.policy_document = doc
        self.policy = dp.Policy(doc)
        # The future producer's exact contract: raw facts and an independent policy binding.
        self.evidence = dict(schema=dp.EVIDENCE_SCHEMA, event='pull_request', repository=self.repo,
                             actor='machine[bot]', pull_request=dict(author_login='machine[bot]',
                             author_type='Bot', head_commit_author_login='machine[bot]',
                             body='<!-- aeos-programme: ' + self.ref + ' -->'),
                             programme=dict(ref=self.ref, state='open', author_login='operator',
                             author_type='User', editors=[], body='Programme'),
                             comment_sources=dict(observed_at=self.now, sources=self.facts))
        self.entry = dp.Entry('scripts/agent_relay/models.py', 'modified', 'a'*64, 'b'*64, None)

    def bind(self):
        self.policy_document['machine_route']['comment_operand'] = self.operand
        self.policy = dp.Policy(self.policy_document)

    def route(self):
        return dp.machine_route(self.policy, self.evidence, None, self.repo, [self.entry], self.now)

    def test_exact_independent_binding_admits(self):
        self.bind()
        self.assertIsNone(self.route())

    def test_absent_binding_refuses_candidate_supplied_operand(self):
        self.evidence['comment_operand'] = self.operand
        self.assertIsNotNone(self.route())

    def test_source_negatives(self):
        self.bind()
        self.assertIsNone(self.route())
        original = copy.deepcopy(self.evidence)
        cases = {
            'untrusted': lambda d: d['comment_sources']['sources'][0]['selected'].update(author_login='foreign'),
            'bot_ratification': lambda d: d['comment_sources']['sources'][0]['selected'].update(author_login='machine[bot]', author_type='Bot'),
            'edited': lambda d: d['comment_sources']['sources'][0]['selected'].update(editors=['operator']),
            'foreign': lambda d: d['comment_sources']['sources'][0].update(ref='other/project#7'),
            'revoked': lambda d: d['comment_sources']['sources'][0].update(state='closed'),
            'stale_body': lambda d: d['comment_sources']['sources'][0].update(body='changed'),
            'stale_comment': lambda d: d['comment_sources']['sources'][0]['selected'].update(body='changed'),
            'stale_clock': lambda d: d['comment_sources'].update(observed_at=self.now-301),
            'missing_source': lambda d: d['comment_sources']['sources'].pop(),
            'duplicate_source': lambda d: d['comment_sources']['sources'].append(copy.deepcopy(d['comment_sources']['sources'][0])),
            'unreadable_edits': lambda d: d['comment_sources']['sources'][0].update(editors=None),
            'incomplete_frontier': lambda d: d['comment_sources']['sources'][0].update(comments_total=2),
            'later_ruling': lambda d: d['comment_sources']['sources'][0]['comments'][0].update(body_sha256='a'*64),
            'selected_id': lambda d: d['comment_sources']['sources'][0]['selected'].update(id=999),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                self.evidence = copy.deepcopy(original)
                mutate(self.evidence)
                self.assertIsNotNone(self.route())

    def test_widening_and_generation_tamper_refuse(self):
        self.bind()
        self.assertIsNone(self.route())
        self.operand['authority']['path_envelope'] = ['scripts/']
        unsigned = {k: v for k, v in self.operand.items() if k != 'generation'}
        self.operand['generation'] = self.ref + '@sha256:' + digest(unsigned)
        self.assertIsNotNone(self.route())
        self.operand['authority']['path_envelope'] = ['scripts/agent_relay/models.py']
        self.assertIsNotNone(self.route())

    def test_body_plus_comment_is_ambiguous(self):
        self.bind()
        self.evidence['programme']['body'] = '```standing-authority\n' + json.dumps(self.authority) + '\n```'
        self.assertIsNotNone(self.route())

    def test_legacy_body_without_binding(self):
        self.evidence['programme']['body'] = '```standing-authority\n' + json.dumps(self.authority) + '\n```'
        self.assertIsNone(self.route())

    def repin(self):
        """Keep digest checks satisfied to isolate provenance from content binding."""
        for binding, fact in zip(self.operand['sources'], self.facts):
            selected = fact['selected']
            fact['comments'] = [{k: selected[k] for k in co.ROW_KEYS}]
            binding['frontier_sha256'] = digest(fact['comments'])
        self.operand['generation'] = self.ref + '@sha256:' + digest(
            {k: v for k, v in self.operand.items() if k != 'generation'})

    def test_bot_and_foreign_ratification_even_when_digest_bound(self):
        self.bind()
        for login, kind in [('machine[bot]', 'Bot'), ('foreign', 'User'), ('operator', 'Bot')]:
            with self.subTest(login=login, kind=kind):
                self.facts[0]['selected'].update(author_login=login, author_type=kind)
                self.repin()
                self.assertIsNotNone(self.route())

    def test_bot_admission_record_is_evidence_not_operator_ratification(self):
        self.bind()
        self.facts[1]['selected'].update(author_login='machine[bot]', author_type='Bot')
        self.repin()
        self.assertIsNone(self.route())

    def test_issue_provenance_refuses_even_when_body_is_bound(self):
        self.bind()
        self.facts[0]['editors'] = ['foreign']
        self.assertIsNotNone(self.route())

    def test_comment_edit_timestamp_without_history_still_refuses(self):
        self.bind()
        self.facts[0]['selected']['created_at'] = '2026-09-19T00:00:00Z'
        self.assertIsNotNone(self.route())

    def test_bad_policy_operand_is_typed_config_failure(self):
        self.bind()
        self.operand['scope'] = 'provider-write'
        with self.assertRaises(dp.PolicyError) as error:
            dp.parse_policy(json.dumps(self.policy_document).encode())
        self.assertEqual(error.exception.code, dp.GATE_CONFIG_INVALID)

    def test_missing_live_operand_facts_refuse(self):
        self.bind()
        del self.evidence['comment_sources']
        self.assertIsNotNone(self.route())

    def test_wrong_programme_and_unrelated_legacy_body(self):
        self.bind()
        self.evidence['programme']['ref'] = 'example/project#10'
        self.assertIsNotNone(self.route())
        self.evidence['pull_request']['body'] = '<!-- aeos-programme: example/project#10 -->'
        authority = dict(self.authority, issue=10)
        self.evidence['programme']['body'] = co.authority_body(authority)
        self.assertIsNone(self.route())

    def test_candidate_evidence_file_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as candidate:
            path = Path(candidate) / 'evidence.json'
            path.write_text(json.dumps(self.evidence))
            result, reason = dp.load_evidence(str(path), candidate_dir=candidate)
            self.assertIsNone(result)
            self.assertEqual(reason, dp.MACHINE_ROUTE_EVIDENCE_MALFORMED)

    def api(self, path, *args):
        self.assertEqual(path, 'graphql')
        number = int(next(a[2:] for a in args if a.startswith('i=')))
        fact = self.facts[number - 7]
        node = fact['selected']
        issue = dict(body=fact['body'], state='OPEN', author=dict(login='operator', __typename='User'),
                     userContentEdits=dict(totalCount=0, nodes=[]), comments=dict(totalCount=1, nodes=[
                         dict(databaseId=node['id'], body=node['body'], createdAt=node['created_at'],
                              updatedAt=node['updated_at'], author=dict(login=node['author_login'],
                              __typename=node['author_type']), userContentEdits=dict(totalCount=0))]))
        return dict(data=dict(repository=dict(issue=issue)))

    def test_collected_facts_enter_real_machine_route(self):
        self.bind()
        self.evidence['comment_sources'] = co.collect(self.operand, self.api, self.now)
        self.assertIsNone(self.route())

    def test_collector_refuses_truncated_edited_deleted_or_graphql_error(self):
        changes = [lambda r: r.update(errors=[dict(message='unavailable')]),
                   lambda r: r['data']['repository']['issue']['comments'].update(totalCount=101),
                   lambda r: r['data']['repository']['issue']['userContentEdits'].update(totalCount=1),
                   lambda r: r['data']['repository']['issue']['comments']['nodes'][0]['userContentEdits'].update(totalCount=1),
                   lambda r: r['data']['repository'].update(issue=None)]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                def api(*args):
                    response = self.api(*args)
                    change(response)
                    return response
                self.assertIn('unavailable', co.collect(self.operand, api, self.now))

    def test_collector_refuses_source_movement(self):
        calls = 0
        def api(*args):
            nonlocal calls
            calls += 1
            response = self.api(*args)
            if calls > 3:
                response['data']['repository']['issue']['body'] = 'moved'
            return response
        self.assertIn('unavailable', co.collect(self.operand, api, self.now))

    def test_closed_operand_guards(self):
        cases = {
            'shape': lambda o: o.update(unrecognised=True),
            'lineage': lambda o: o['sources'][1].update(role='ratification'),
            'source_shape': lambda o: o['sources'][1].update(extra=True),
            'source_identity': lambda o: o['sources'][1].update(
                ref=o['sources'][0]['ref'], comment_id=o['sources'][0]['comment_id']),
            'authority_shape': lambda o: o['authority'].update(extra=True),
            'programme': lambda o: o['authority'].update(issue=8),
            'expiry': lambda o: o['authority'].update(not_after='2026-09-23T00:00:00Z'),
            'scope': lambda o: o['authority'].update(path_envelope=['scripts/agent_relay/other.py']),
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                operand = copy.deepcopy(self.operand)
                change(operand)
                operand['generation'] = self.ref + '@sha256:' + digest(
                    {k: v for k, v in operand.items() if k != 'generation'})
                with self.assertRaises(ValueError):
                    co.validate(operand, dp.programme_block)

    def test_resolver_guards_without_downstream_masking(self):
        self.bind()
        def resolve():
            return co.resolve(self.operand, self.evidence, self.evidence['programme'],
                              self.policy, dp.programme_block, self.now)
        self.assertIsNotNone(resolve())
        original = copy.deepcopy((self.operand, self.evidence))
        for case in ('programme', 'ambiguity', 'body', 'programme_body', 'id', 'projection'):
            with self.subTest(case=case):
                self.operand, self.evidence = copy.deepcopy(original)
                fact = self.evidence['comment_sources']['sources'][0]
                binding = self.operand['sources'][0]
                if case == 'programme':
                    self.evidence['programme']['ref'] = 'other/project#7'
                elif case == 'ambiguity':
                    fact['body'] = co.authority_body(self.authority)
                    self.evidence['programme']['body'] = fact['body']
                    binding['issue_body_sha256'] = hashlib.sha256(fact['body'].encode()).hexdigest()
                elif case == 'body':
                    fact['body'] = self.evidence['programme']['body'] = 'changed'
                elif case == 'programme_body':
                    self.evidence['programme']['body'] = 'changed'
                elif case == 'id':
                    binding['comment_id'] = 999
                elif case == 'projection':
                    fact['selected']['author_login'] = 'machine[bot]'
                    # Admission permits the principal but still requires exact row equality.
                    fact = self.evidence['comment_sources']['sources'][1]
                    fact['selected']['author_login'] = 'machine[bot]'
                    fact['selected']['author_type'] = 'Bot'
                    self.evidence['comment_sources']['sources'][0]['selected']['author_login'] = 'operator'
                self.operand['generation'] = self.ref + '@sha256:' + digest(
                    {k: v for k, v in self.operand.items() if k != 'generation'})
                self.assertIsNone(resolve())

    def test_collector_duplicate_selected_is_unavailable(self):
        def api(*args):
            response = self.api(*args)
            connection = response['data']['repository']['issue']['comments']
            connection['nodes'] *= 2
            connection['totalCount'] = 2
            return response
        self.assertIn('unavailable', co.collect(self.operand, api, self.now))

    def test_later_revocation_or_conflict_changes_frontier(self):
        self.bind()
        fact = self.facts[0]
        later = dict(fact['comments'][0], id=701, body_sha256=hashlib.sha256(b'Revoked').hexdigest())
        fact['comments'].append(later)
        fact['comments_total'] = 2
        self.assertIsNotNone(self.route())

    def test_workflow_collects_from_trusted_policy_and_supports_predecessor(self):
        import os
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch
        workflow = (Path(__file__).resolve().parents[2] /
                    '.github/workflows/aeos-merge-ready.yml').read_text()
        script = workflow.split("python3 - <<'PY'\n", 1)[1].split('\n          PY', 1)[0]
        import textwrap
        script = textwrap.dedent(script)
        self.bind()
        def run(argv, **kwargs):
            self.assertEqual(argv[:2], ['gh', 'api'])
            path, *args = argv[2:]
            if '/commits/' in path:
                result = {'author': {'login': 'machine[bot]'}}
            elif path.startswith('repos/'):
                result = {'state': 'open', 'body': 'Programme',
                          'user': {'login': 'operator', 'type': 'User'}}
            else:
                result = self.api(path, *args)
            return SimpleNamespace(returncode=0, stdout=json.dumps(result))
        with tempfile.TemporaryDirectory() as temp:
            event = Path(temp) / 'event.json'
            output = Path(temp) / 'evidence.json'
            event.write_text(json.dumps({'pull_request': {
                'user': {'login': 'machine[bot]', 'type': 'Bot'}, 'head': {'sha': 'a'*40},
                'body': '<!-- aeos-programme: ' + self.ref + ' -->'}}))
            environment = dict(AEOS_EVENT_PATH=str(event), AEOS_ACTOR_EVIDENCE=str(output),
                               AEOS_EVENT_NAME='pull_request', AEOS_REPOSITORY=self.repo,
                               AEOS_ACTOR='machine[bot]')
            for policy in (self.policy, SimpleNamespace()):
                with self.subTest(predecessor=not hasattr(policy, 'comment_operand')):
                    with patch.dict(os.environ, environment), patch('subprocess.run', run), \
                            patch.object(dp, 'load_policy', return_value=policy) as load, \
                            patch('time.time', return_value=self.now), patch.object(sys, 'path', sys.path[:]):
                        exec(compile(script, '<trusted evidence workflow>', 'exec'), {})
                    load.assert_called_once_with('policy/aeos')
                    result = json.loads(output.read_text())
                    self.assertNotIn('unavailable', result)
                    if hasattr(policy, 'comment_operand'):
                        self.assertIsNone(dp.machine_route(self.policy, result, None,
                                                         self.repo, [self.entry], self.now))
                    else:
                        self.assertNotIn('comment_sources', result)
