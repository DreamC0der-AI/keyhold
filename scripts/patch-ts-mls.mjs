// ts-mls 1.6.4 rejects valid ratchet trees: when it checks a parent node's unmerged leaves, it
// demands that every non-blank node on each such leaf's direct path (above the parent too) has
// the very same unmerged list. RFC 9420 (7.9.2) only asks that the nodes between the leaf and that
// parent list the leaf. With two people added by pre-key under one non-blank parent, joining by
// the Welcome failed ("non-blank intermediate node must list leaf node in its unmerged_leaves").
// ts-mls 2.0 has the RFC check; this applies the same change to 1.6.4 after every install.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

// The installed copy, found the way Node looks for packages: node_modules here or in a parent.
let file;
for (let dir = resolve(process.cwd()); ; dir = dirname(dir)) {
  const f = join(dir, 'node_modules/ts-mls/dist/src/clientState.js');
  if (existsSync(f)) {
    file = f;
    break;
  }
  if (dirname(dir) === dir) process.exit(0); // not installed here
}
const src = readFileSync(file, 'utf8');
const before = `                for (const parentIdx of dp) {
                    const dpNode = tree[parentIdx];
                    if (dpNode !== undefined) {
                        if (dpNode.nodeType !== "parent")
                            return new InternalError("Expected parent node");
                        if (!arraysEqual(dpNode.parent.unmergedLeaves, n.parent.unmergedLeaves))`;
const after = `                for (const parentIdx of dp) {
                    if (parentIdx === toNodeIndex(i))
                        break; // patched (RFC 9420 7.9.2): only the nodes below this parent
                    const dpNode = tree[parentIdx];
                    if (dpNode !== undefined) {
                        if (dpNode.nodeType !== "parent")
                            return new InternalError("Expected parent node");
                        if (!dpNode.parent.unmergedLeaves.includes(unmergedLeaf))`;
if (src.includes(after)) process.exit(0);
if (!src.includes(before)) {
  console.error(`patch-ts-mls: ${file} doesn't look like ts-mls 1.6.4; check whether the unmerged-leaves fix is still needed.`);
  process.exit(1);
}
writeFileSync(file, src.replace(before, after));
console.log('patch-ts-mls: applied the unmerged-leaves fix');
