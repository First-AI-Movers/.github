"""Complete authenticated frontiers, including a selected source on page six."""
import copy
import unittest

import test_comment_operand as fixtures

co, dp = fixtures.co, fixtures.dp


class PaginationTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.CommentOperandTests()
        self.f.setUp()
        self.f.bind()
        self.calls = []
        self.change = lambda issue, page, observation: None
        self.observation = 0
        self.page_size = 100

    def api(self, path, *args):
        response = self.f.api(path, *args)
        issue = response['data']['repository']['issue']
        if issue['number'] != 9:
            return response
        cursor = next((a[len('cursor='):] for a in args if a.startswith('cursor=')), None)
        query = next(a[len('query='):] for a in args if a.startswith('query='))
        if 'after:$cursor' not in ''.join(query.split()):
            cursor = None  # GraphQL cannot apply a variable the connection does not use.
        start = int(cursor) if cursor is not None else 0
        if start == 0:
            self.observation += 1
        self.calls.append(start)
        connection = issue['comments']
        selected = connection['nodes'][0]
        end = min(start + self.page_size, 582)
        nodes = [dict(copy.deepcopy(selected), databaseId=i + 319) for i in range(start, end)]
        connection.update(totalCount=582, nodes=nodes,
                          pageInfo=dict(hasNextPage=end < 582, endCursor=str(end)))
        self.change(issue, start // self.page_size, self.observation)
        return response

    def collect(self):
        return co.collect(self.f.operand, self.api, self.f.now)

    def test_all_582_comments_and_page_six_selection_reach_route(self):
        result = self.collect()
        self.assertNotIn('unavailable', result)
        fact = result['sources'][2]
        self.assertEqual([c['id'] for c in fact['comments']], list(range(319, 901)))
        self.assertEqual(fact['selected']['id'], 900)
        self.assertEqual(self.calls, [0, 100, 200, 300, 400, 500] * 2)
        # Independently bind the full observed fixture, never just its first page.
        self.f.operand['sources'][2]['frontier_sha256'] = fixtures.digest(fact['comments'])
        self.f.operand['generation'] = self.f.ref + '@sha256:' + fixtures.digest(
            {k: v for k, v in self.f.operand.items() if k != 'generation'})
        self.f.evidence['comment_sources'] = result
        # Exercise the existing serialized evidence size/trust boundary too.
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'evidence.json'
            path.write_text(json.dumps(self.f.evidence))
            evidence, reason = dp.load_evidence(str(path))
            self.assertIsNone(reason)
            self.assertIsNone(dp.machine_route(self.f.policy, evidence, reason,
                                              self.f.repo, [self.f.entry], self.f.now))

    def test_complete_collection_still_refuses_old_frontier(self):
        result = self.collect()
        self.assertNotIn('unavailable', result)
        self.f.evidence['comment_sources'] = result
        self.assertEqual(self.f.route(), dp.MACHINE_ROUTE_AUTHORITY_BLOCK_INVALID)

    def test_bad_page_or_provenance_never_emits_partial_facts(self):
        cases = {
            'missing_page_info': lambda i: i['comments'].pop('pageInfo'),
            'cursor_missing': lambda i: i['comments']['pageInfo'].update(endCursor=None),
            'cursor_cycle': lambda i: i['comments']['pageInfo'].update(endCursor='100'),
            'ambiguous_next': lambda i: i['comments']['pageInfo'].update(hasNextPage=1),
            'early_terminal': lambda i: i['comments']['pageInfo'].update(hasNextPage=False),
            'empty_page': lambda i: i['comments'].update(nodes=[]),
            'count_drift': lambda i: i['comments'].update(totalCount=581),
            'count_untyped': lambda i: i['comments'].update(totalCount='582'),
            'count_over_bound': lambda i: i['comments'].update(totalCount=1001),
            'foreign_issue': lambda i: i.update(number=8),
            'foreign_repository': lambda i: i['repository'].update(nameWithOwner='foreign/project'),
            'identity_drift': lambda i: i.update(id='replacement'),
            'body_drift': lambda i: i.update(body='changed'),
            'revocation': lambda i: i.update(state='CLOSED'),
            'hidden_comment': lambda i: i['comments']['nodes'][0].update(isMinimized=True),
            'unknown_visibility': lambda i: i['comments']['nodes'][0].pop('isMinimized'),
            'deleted_comment': lambda i: i['comments']['nodes'].__setitem__(0, None),
            'duplicate_id': lambda i: i['comments']['nodes'][0].update(databaseId=319),
            'unknown_id': lambda i: i['comments']['nodes'][0].update(databaseId=None),
            'unreadable_author': lambda i: i['comments']['nodes'][0].update(author=None),
            'editor_type': lambda i: i['userContentEdits'].update(totalCount=1, nodes=[
                {'editor': {'login': 'operator', '__typename': 'Bot'}}]),
            'deleted_editor': lambda i: i['userContentEdits'].update(totalCount=1, nodes=[{'editor': None}]),
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                self.change = lambda i, p, o, change=change: change(i) if p == 1 else None
                self.assertEqual(self.collect(), {'unavailable': 'COMMENT_SOURCE_UNAVAILABLE'})

    def test_selected_comment_absent_or_edited_on_last_page_refuses(self):
        for name in ('absent', 'edited', 'unknown_edits'):
            with self.subTest(name=name):
                def change(issue, page, observation):
                    if page == 5:
                        selected = issue['comments']['nodes'][-1]
                        if name == 'absent':
                            selected['databaseId'] = 901
                        else:
                            selected['userContentEdits']['totalCount'] = 1 if name == 'edited' else False
                self.change = change
                self.assertEqual(self.collect(), {'unavailable': 'COMMENT_SOURCE_UNAVAILABLE'})

    def test_later_page_changes_between_complete_observations_refuse(self):
        def change(issue, page, observation):
            if page == 4 and observation == 2:
                issue['comments']['nodes'][0]['body'] = 'Later revocation'
        self.change = change
        self.assertEqual(self.collect(), {'unavailable': 'COMMENT_SOURCE_UNAVAILABLE'})

    def test_page_budget_bounds_short_nonterminal_pages(self):
        self.page_size = 1
        self.assertEqual(self.collect(), {'unavailable': 'COMMENT_SOURCE_UNAVAILABLE'})
        self.assertEqual(len(self.calls), 10)

    def test_issue_identity_change_between_observations_refuses(self):
        self.change = lambda i, p, o: i.update(id='replacement') if o == 2 else None
        self.assertEqual(self.collect(), {'unavailable': 'COMMENT_SOURCE_UNAVAILABLE'})

    def test_foreign_identity_and_editor_type_even_when_stable_refuse(self):
        for name in ('repository', 'number', 'editor'):
            with self.subTest(name=name):
                def change(issue, page, observation):
                    if name == 'repository':
                        issue['repository']['nameWithOwner'] = 'foreign/project'
                    elif name == 'number':
                        issue['number'] = 8
                    else:
                        issue['userContentEdits'] = dict(totalCount=1, nodes=[
                            {'editor': {'login': 'operator', '__typename': 'Bot'}}])
                self.change = change
                self.assertEqual(self.collect(), {'unavailable': 'COMMENT_SOURCE_UNAVAILABLE'})

    def test_terminal_page_must_cover_total_even_if_selected_is_present(self):
        self.f.operand['sources'][2]['comment_id'] = 319
        self.change = lambda i, p, o: i['comments']['pageInfo'].update(hasNextPage=False)
        self.assertEqual(self.collect(), {'unavailable': 'COMMENT_SOURCE_UNAVAILABLE'})

    def test_counts_must_be_integers_not_boolean_aliases(self):
        for field in ('comments', 'userContentEdits'):
            with self.subTest(field=field):
                def api(*args):
                    response = self.f.api(*args)
                    response['data']['repository']['issue'][field]['totalCount'] = field == 'comments'
                    return response
                self.assertEqual(co.collect(self.f.operand, api, self.f.now),
                                 {'unavailable': 'COMMENT_SOURCE_UNAVAILABLE'})

    def test_complete_user_edit_history_preserves_legacy_operand_shape(self):
        def api(*args):
            response = self.f.api(*args)
            response['data']['repository']['issue']['userContentEdits'] = dict(totalCount=1, nodes=[
                {'editor': {'login': 'operator', '__typename': 'User'}}])
            return response
        self.f.evidence['comment_sources'] = co.collect(self.f.operand, api, self.f.now)
        self.assertIsNone(self.f.route())
