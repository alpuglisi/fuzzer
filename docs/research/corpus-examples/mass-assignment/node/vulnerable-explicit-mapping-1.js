// Manufactured, representative of the object-spread mass-assignment
// anti-pattern (spreading req.body into a persisted object literal).
router.patch('/api/user-profile', requireAuth, async (req, res) => {
  const profile = await Profile.findOne({ userId: req.user.id });

  // Spreads every key the client sent onto the entity, including
  // "userId" or "role" if the client happens to include them -- the
  // route's own requireAuth only established *who* is calling, not
  // *which fields* they may change.
  Object.assign(profile, { ...req.body });

  await profile.save();
  res.json(profile);
});
