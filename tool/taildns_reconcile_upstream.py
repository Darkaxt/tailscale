"""Resolve only the reviewed captive-dial return hunk, retaining all other merged bytes."""
import re,subprocess,sys
from pathlib import Path

PATH='net/captivedetection/captivedetection.go'
REVIEWED=('024d13639009e2ce44bc678c09d1b55c018c2b02',
          '982c45d279ddb553451fe744a4476ed42d4f6714',
          'dd0950c2980d2aadedd576a77528a1b8159dbe4b')
FORK_LINE=b'\t\t\treturn setSocketInterfaceIndex(c, ifIndex, network, d.logf)\n'
CANONICAL_LINE=b'\t\t\treturn setSocketInterfaceIndex(c, ifIndex, d.logf)\n'

def resolve(blobs,merged,upstream):
    if tuple(blobs)!=REVIEWED or not re.fullmatch(r'[0-9a-f]{40}',upstream):
        raise RuntimeError('unreviewed-captive-merge-input')
    block=b'<<<<<<< HEAD\n'+FORK_LINE+b'=======\n'+CANONICAL_LINE+b'>>>>>>> '+upstream.encode()+b'\n'
    if merged.count(block)!=1 or merged.count(b'<<<<<<< ')!=1 or merged.count(b'>>>>>>> ')!=1:
        raise RuntimeError('unreviewed-captive-conflict-hunk')
    # Replace the exact conflict inside Git's merged file. Never rebuild the file
    # from either side and thereby discard already-merged non-conflicting edits.
    return merged.replace(block,FORK_LINE,1)

def main(upstream):
    raw=subprocess.check_output(['git','ls-files','--unmerged','-z','--',PATH])
    if not raw:return
    stages={}
    for item in raw.split(b'\0'):
        if not item:continue
        metadata,path=item.split(b'\t');mode,blob,stage=metadata.split()
        if path.decode()!=PATH or mode!=b'100644':raise RuntimeError('unreviewed-captive-index')
        stages[int(stage)]=blob.decode()
    if set(stages)!={1,2,3}:raise RuntimeError('unreviewed-captive-stages')
    path=Path(PATH);merged=path.read_bytes()
    path.write_bytes(resolve(tuple(stages[i] for i in (1,2,3)),merged,upstream))
    subprocess.run(['git','add','--',PATH],check=True)
    print('Resolved reviewed captive dial hunk; retained context callback and network-family binding.')

if __name__=='__main__':main(sys.argv[1])
