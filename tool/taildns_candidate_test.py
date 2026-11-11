"""Exercise the real workflow composition boundary with synthetic Git histories."""
import os,shutil,subprocess,tempfile,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
WORKFLOW=Path(os.environ.get('TAILDNS_CANDIDATE_WORKFLOW',ROOT/'.github/workflows/taildns-upstream-candidate.yml'))
BASH=Path('C:/Program Files/Git/bin/bash.exe') if os.name=='nt' else Path(shutil.which('bash'))

class CandidatePolicyTest(unittest.TestCase):
    def git(self,*args):
        return subprocess.check_output(['git',*args],cwd=self.repo,encoding='utf-8').strip()

    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='taildns-candidate-')
        self.addCleanup(self.temporary.cleanup)
        self.repo=Path(self.temporary.name)/'repository';self.repo.mkdir()
        self.git('init','-b','main')
        self.git('config','user.name','TailDNS synthetic regression')
        self.git('config','user.email','synthetic@example.invalid')
        self.workflows=self.repo/'.github/workflows';self.workflows.mkdir(parents=True)
        self.workflow=self.workflows/'natlab-test.yml';self.workflow.write_text('policy: common\n')
        (self.workflows/'windows-nightly.yml').write_text('nightly: common\n')
        (self.repo/'shared.txt').write_text('common\n')
        (self.repo/'fork.txt').write_text('original\n')
        self.git('add','.');self.git('commit','-m','common')
        self.common=self.git('rev-parse','HEAD')
        self.git('checkout','-b','fork')
        self.workflow.write_text('policy: reviewed-fork\n')
        self.git('rm','.github/workflows/windows-nightly.yml')
        (self.repo/'fork.txt').write_text('retained fork behavior\n')
        self.git('add','.');self.git('commit','-m','fork-owned policies and runtime')

    def compose(self,source_conflict=False,workflow_conflict=True):
        if source_conflict:
            (self.repo/'shared.txt').write_text('fork source\n')
            self.git('add','.');self.git('commit','-m','fork source change')
        self.base=self.git('rev-parse','HEAD')
        self.git('checkout','main')
        if workflow_conflict:
            self.workflow.write_text('policy: canonical-new\n')
            (self.workflows/'windows-nightly.yml').write_text('nightly: canonical-new\n')
        else:
            (self.workflows/'new-upstream.yml').write_text('unreviewed upstream workflow\n')
        (self.repo/'shared.txt').write_text('canonical source\n')
        self.git('add','.');self.git('commit','-m','canonical changes')
        self.upstream=self.git('rev-parse','HEAD');self.git('checkout','fork')
        lines=WORKFLOW.read_text(encoding='utf-8').splitlines()
        start=next(i for i,line in enumerate(lines) if line.strip()=='git checkout -B "$branch" "$base_head"')
        end=next(i for i,line in enumerate(lines[start:],start) if line.strip()=='if [[ "$DRY_RUN" == true ]]; then')
        script=Path(self.temporary.name)/'compose.sh'
        script.write_text('set -euo pipefail\n'+'\n'.join(line[10:] for line in lines[start:end])+'\n',encoding='utf-8',newline='\n')
        env=os.environ.copy();env.update(branch='synthetic-candidate',base_head=self.base,upstream_head=self.upstream,GITHUB_STEP_SUMMARY=str(Path(self.temporary.name)/'summary.md'))
        return subprocess.run([str(BASH),str(script)],cwd=self.repo,env=env,capture_output=True,text=True,encoding='utf-8')

    def test_workflow_conflicts_preserve_policy_and_runtime_history(self):
        result=self.compose();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(self.workflow.read_text(),'policy: reviewed-fork\n')
        self.assertFalse((self.workflows/'windows-nightly.yml').exists())
        self.assertEqual((self.repo/'fork.txt').read_text(),'retained fork behavior\n')
        self.assertEqual((self.repo/'shared.txt').read_text(),'canonical source\n')
        self.assertEqual(self.git('show','-s','--format=%P').split(),[self.base,self.upstream])
        self.assertEqual(self.git('status','--porcelain'),'')

    def test_source_conflict_still_aborts_without_candidate(self):
        result=self.compose(source_conflict=True);self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.git('rev-parse','HEAD'),self.base)
        self.assertEqual(self.git('status','--porcelain'),'')
        self.assertEqual((self.repo/'shared.txt').read_text(),'fork source\n')

    def test_clean_merge_does_not_import_unreviewed_workflow(self):
        result=self.compose(workflow_conflict=False);self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse((self.workflows/'new-upstream.yml').exists())
        self.assertEqual(self.git('diff',self.base,'HEAD','--','.github/workflows'),'')
        self.assertEqual((self.repo/'shared.txt').read_text(),'canonical source\n')
        self.git('merge-base','--is-ancestor',self.upstream,'HEAD')

if __name__=='__main__':unittest.main()
