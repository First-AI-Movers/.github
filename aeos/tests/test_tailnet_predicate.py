"""Synthetic candidates only: the tailnet admission conjunct and publication barrier."""
import copy
import json
import os
from pathlib import Path
import tempfile
from unittest import mock

import pytest
import test_accepted_change as accepted_tests
import accepted_change as ac
import derivation_policy as dp
import merge_ready_gate as gate
from test_merge_ready_gate import Repo, git
from test_accepted_change import (entry, evidence, document, NOW, ISSUED, NOT_AFTER, epoch,
                                  MACHINE, OPERATOR)

REPO = 'First-AI-Movers/tailnet-policy'
CODE = gate.TAILNET_POLICY_CHANGE_NOT_ADMITTED


@pytest.fixture
def candidate(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    return Repo(str(root))


def run(repo, path='policy.hujson', *, entries=None, ev=None, now=NOW, repository=REPO, event='pull_request',
        prepare=None):
    if prepare:
        prepare(repo)
    else:
        repo.write(path, 'X = 2\n' if path.endswith('.py') else '{}\n')
    head = repo.commit('candidate')
    raw = dp.raw_diff(repo.root, repo.base, head)
    changes, _ = dp.protected_diff(repo.root, repo.base, head, set(dp.touched_paths(raw)))
    if callable(entries):
        entries = entries(changes)
    with tempfile.TemporaryDirectory() as temp:
        Path(temp, dp.POLICY_FILE).write_bytes(document(entries or []))
        evidence_path = None
        if ev is not None:
            ev = copy.deepcopy(ev)
            ev['repository'] = repository
            ev['pull_request']['head_sha'] = head
            if ev['pull_request'].get('approval'):
                for review in ev['pull_request']['approval'].get('reviews', []):
                    review['commit_id'] = head
            evidence_path = str(Path(temp, 'evidence.json'))
            Path(evidence_path).write_text(json.dumps(ev))
        return gate.evaluate(candidate_dir=repo.root, repository=repository, base_sha=repo.base, head_sha=head,
                             event_name=event, policy_dir=temp, evidence_path=evidence_path, now=lambda: now)


def accepted(changes, **kwargs):
    return [entry(changes, repository=REPO, **kwargs)]


def refused(report, reason=None):
    findings = [f for f in report.findings if f.code == CODE]
    assert len(findings) == 1, [(f.code, f.detail) for f in report.findings]
    assert findings[0].path in findings[0].detail
    if reason:
        assert reason in findings[0].detail


def test_policy_without_admission(candidate):
    refused(run(candidate))


def test_workflow_without_admission(candidate):
    workflow = 'name: test\non: pull_request\npermissions: {}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n'
    report = run(candidate, prepare=lambda r: r.write('.github/workflows/test.yml', workflow))
    refused(report)
    assert [f.code for f in report.findings] == [CODE]  # The strict lane otherwise passes.


def test_python_without_admission(candidate):
    refused(run(candidate, 'tests/x.py'))


def test_github_markdown_without_admission(candidate):
    refused(run(candidate, '.GiThUb/a.MD'))


def test_symlink_markdown_without_admission(candidate):
    def prepare(r):
        os.unlink(Path(r.root, 'README.md'))
        os.symlink('other', Path(r.root, 'README.md'))
    refused(run(candidate, prepare=prepare))


def test_rename_non_doc_to_doc(candidate):
    candidate.write('policy.hujson', '{}\n')
    candidate.base = candidate.commit('seed')
    refused(run(candidate, prepare=lambda r: os.rename(Path(r.root, 'policy.hujson'), Path(r.root, 'x.md'))))


def test_digest_mismatch(candidate):
    refused(run(candidate, ev=evidence(), entries=lambda c: accepted(c, protected_diff_sha256='f' * 64)))


def test_expired(candidate):
    refused(run(candidate, ev=evidence(), entries=accepted, now=epoch(NOT_AFTER)), ac.ACCEPTED_CHANGE_EXPIRED)


def test_disabled(candidate):
    refused(run(candidate, ev=evidence(), entries=lambda c: accepted(c, activation='disabled')), ac.ACCEPTED_CHANGE_DISABLED)


def test_not_yet_valid(candidate):
    refused(run(candidate, ev=evidence(), entries=accepted, now=epoch(ISSUED)-1), ac.ACCEPTED_CHANGE_NOT_YET_VALID)


def test_accepted_records_dependence(candidate):
    report = run(candidate, ev=evidence(), entries=accepted)
    assert report.passed, [(f.code, f.detail) for f in report.findings]
    assert report.accepted_change['repository'] == REPO
    assert not report.approval_dependent


def test_exact_head_approval(candidate):
    review = {'id': 1, 'login': OPERATOR, 'type': 'User', 'state': 'APPROVED', 'commit_id': 'a'*40,
              'submitted_at': '2026-10-04T21:00:00Z'}
    report = run(candidate, ev=evidence(reviews=[review]))
    assert report.passed
    assert report.approval_dependent
    assert report.accepted_change is None


def test_operator_authorship_is_not_an_admission(candidate):
    # ADR section 2: authorship and the run actor are not a decision about these bytes.
    refused(run(candidate, ev=evidence(pr_author=OPERATOR, actor=OPERATOR)))
    report = run(candidate, ev=evidence(pr_author=OPERATOR, actor=OPERATOR, head_commit=MACHINE,
                                        context='HEAD_MOVED', reviews=(), barrier=None))
    refused(report)
    assert not report.approval_dependent and report.accepted_change is None


def test_bot_actor_on_operator_pr(candidate):
    refused(run(candidate, ev=evidence(pr_author=OPERATOR)))


def test_documentation_without_evidence(candidate):
    assert run(candidate, 'guide.MD').passed


def test_doc_deletion(candidate):
    assert run(candidate, prepare=lambda r: r.remove('README.md')).passed


def test_third_repository_unaffected(candidate):
    assert run(candidate, repository='First-AI-Movers/third').passed


def test_other_repository_no_extra_reads():
    with mock.patch.object(dp, 'raw_diff', side_effect=AssertionError('read')):
        gate.tailnet_predicate(None, '', 'other/repo', '', '', '', '', None, lambda: NOW)


def test_merge_group_non_documentation(candidate):
    refused(run(candidate, entries=accepted, ev=evidence(pr_author=OPERATOR, actor=OPERATOR), event='merge_group'))


def test_agent_toolkit_entry_never_admits_tailnet(candidate):
    refused(run(candidate, ev=evidence(), path='scripts/agent_relay/dispatcher.py',
                entries=lambda c: [entry(c)]))


def test_tailnet_entry_never_admits_agent_toolkit(candidate):
    # Exercise the shared route directly so a synthetic derivation closure is unnecessary.
    from test_accepted_change import change, policy, route
    changes = [change()]
    assert route(evidence(), pol=policy(accepted(changes))) is not None


@pytest.mark.parametrize('field,value', [('actor', OPERATOR), ('head_commit', OPERATOR), ('barrier', None),
                                        ('body', '<!-- scoped-machine-grant: First-AI-Movers/agent-toolkit#9@sha256:'+'c'*64+' -->'),
                                        ('context', 'HEAD_MOVED')])
def test_acceptance_identity_and_context(candidate, field, value):
    refused(run(candidate, ev=evidence(**{field: value}), entries=accepted))


def test_acceptance_exact_paths(candidate):
    refused(run(candidate, ev=evidence(), entries=lambda c: accepted(c, paths=['other'])), ac.ACCEPTED_CHANGE_PATHS_MISMATCH)


def test_acceptance_regular_file(candidate):
    def prepare(r):
        os.symlink('other', Path(r.root, 'policy.hujson'))
    refused(run(candidate, prepare=prepare, ev=evidence(), entries=accepted), ac.ACCEPTED_CHANGE_NOT_REGULAR_FILE)


def test_tailnet_loader_allows_workflow_and_policy():
    from test_accepted_change import policy, change
    assert len(policy(accepted([change('policy.hujson'), change('.github/workflows/test.yml')])).accepted_changes) == 1


def test_same_digest_can_be_accepted_in_two_repositories():
    from test_accepted_change import policy, change
    c = [change()]
    assert len(policy([entry(c), *accepted(c)]).accepted_changes) == 2


def test_class_hook_admits_nothing():
    assert gate.tailnet_class_admits([]) is False


@pytest.mark.parametrize('state,expected', [('removed', ac.ACCEPTED_CHANGE_REVOKED),
                                          ('disabled', ac.ACCEPTED_CHANGE_DISABLED), ('expired', ac.ACCEPTED_CHANGE_EXPIRED)])
def test_tailnet_publication_withdrawal(state, expected):
    helper = accepted_tests.PublicationRecheckTests()
    accepted_entry = accepted([])[0]
    accepted_entry['paths'] = ['policy.hujson']
    dependence = {k: accepted_entry[k] for k in ('repository', 'protected_diff_sha256')}
    entries = [] if state == 'removed' else [accepted_entry]
    if state == 'disabled':
        accepted_entry['activation'] = 'disabled'
    code, out, _ = helper.run_step(marker=helper.marker(dependence), entries=entries, repository=REPO,
                                   now=epoch(NOT_AFTER) if state == 'expired' else NOW)
    assert code == 1
    assert expected in out[1]


@pytest.mark.parametrize('event,author', [('pull_request', MACHINE), ('merge_group', '')])
def test_tailnet_unreadable_marker(event, author):
    helper = accepted_tests.PublicationRecheckTests()
    code, out, _ = helper.run_step(marker=None, entries=[], repository=REPO, event=event, author=author)
    assert code == 1
    assert ac.ACCEPTED_CHANGE_DEPENDENCE_UNREADABLE in out[1]


def test_gitlink_markdown_without_admission(candidate):
    git(candidate.root, 'update-index', '--add', '--cacheinfo', '160000', 'f'*40, 'link.md')
    head = candidate.commit_index('gitlink')
    report = gate.evaluate(candidate_dir=candidate.root, repository=REPO, base_sha=candidate.base,
                           head_sha=head, event_name='pull_request')
    refused(report)


def test_case_insensitive_repository(candidate):
    refused(run(candidate, repository=REPO.upper()))


def test_unpinned_operator_author(candidate):
    refused(run(candidate, ev=evidence(pr_author='other-user', actor=OPERATOR)))


def test_operator_author_must_be_user(candidate):
    ev = evidence(pr_author=OPERATOR, actor=OPERATOR)
    ev['pull_request']['author_type'] = 'Bot'
    refused(run(candidate, ev=ev))


def test_acceptance_machine_author(candidate):
    refused(run(candidate, ev=evidence(pr_author='other-user'), entries=accepted))


def test_acceptance_evidence_repository(candidate):
    # Use the predicate directly to preserve deliberately mismatched evidence.
    candidate.write('policy.hujson', '{}\n')
    head = candidate.commit('candidate')
    changes, _ = dp.protected_diff(candidate.root, candidate.base, head, {'policy.hujson'})
    report = gate.Report()
    with mock.patch.object(dp, 'load_policy', return_value=dp.parse_policy(document(accepted(changes)))), \
            mock.patch.object(dp, 'load_evidence', return_value=(evidence(), None)):
        gate.tailnet_predicate(report, candidate.root, REPO, candidate.base, head, 'pull_request', '', None, lambda: NOW)
    refused(report, dp.MACHINE_ROUTE_REPOSITORY_MISMATCH)


def test_acceptance_covers_all_changed_paths(candidate):
    def prepare(r):
        r.write('policy.hujson', '{}\n')
        r.write('notes.md', 'additional documentation\n')
    refused(run(candidate, prepare=prepare, ev=evidence(), entries=lambda c: accepted([x for x in c if x.path == 'policy.hujson'])))


def test_documentation_modes_on_deleted_side(candidate):
    os.unlink(Path(candidate.root, 'README.md'))
    os.symlink('other', Path(candidate.root, 'README.md'))
    candidate.base = candidate.commit('seed symlink')
    refused(run(candidate, prepare=lambda r: r.remove('README.md')))


def test_doc_rename_to_non_doc(candidate):
    refused(run(candidate, prepare=lambda r: os.rename(Path(r.root, 'README.md'), Path(r.root, 'policy.hujson'))))



def test_accepted_change_keeps_generic_floor(candidate):
    report = run(candidate, ev=evidence(), entries=accepted,
                 prepare=lambda r: r.write('tests/x.py', 'def broken(\n'))
    assert report.accepted_change is not None
    assert not report.passed
    assert CODE not in [f.code for f in report.findings]


def test_executable_documentation(candidate):
    def prepare(r):
        r.write('guide.MD', 'regular executable documentation\n')
        os.chmod(Path(r.root, 'guide.MD'), 0o755)
    assert run(candidate, prepare=prepare).passed


@pytest.mark.parametrize('path', ['../policy.hujson', '/policy.hujson', 'a//b', 'policy.*', '.github/../x'])
def test_tailnet_entries_require_exact_paths(path):
    from test_accepted_change import policy, change
    with pytest.raises(dp.PolicyError):
        policy(accepted([change(path)]))
