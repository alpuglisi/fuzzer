// Manufactured vulnerable variant, derived from
// idiomatic-job-spec-no-eval-2.js. The job payload carries executable
// script text, run via Node's vm module -- a well-documented real
// anti-pattern (Node's own vm docs warn vm is NOT a security sandbox).
const vm = require('vm');

async function processJob(rawPayload) {
  const job = JSON.parse(rawPayload); // { script: "...", context: {...} }

  // vm.runInNewContext() is NOT a security boundary (Node's own docs say
  // so explicitly) -- arbitrary job-authored script runs with full
  // access to whatever globals `job.context` exposes, and vm sandbox
  // escapes are a well-documented real vulnerability class.
  return vm.runInNewContext(job.script, job.context);
}
