// Manufactured, representative of a safe background-job design: the job
// payload is a plain, declarative JSON spec naming a pre-registered
// handler, never executable code.
const handlers = { sendWelcomeEmail, resizeImage, syncCalendar };

async function processJob(rawPayload) {
  const job = JSON.parse(rawPayload); // { type: "resizeImage", args: {...} }

  const handler = handlers[job.type];
  if (!handler) {
    throw new Error(`Unknown job type: ${job.type}`);
  }
  return handler(job.args);
}
