// Manufactured, representative of explicit field-by-field mapping (the
// most conservative real-world mitigation, common in hand-rolled Express
// APIs that don't use an ORM allowlist option).
router.patch('/api/user-profile', requireAuth, async (req, res) => {
  const profile = await Profile.findOne({ userId: req.user.id });

  // Every persisted field is named explicitly; a new field added to
  // req.body by a client has no effect unless a developer also adds a
  // corresponding line here.
  profile.displayName = req.body.displayName;
  profile.bio = req.body.bio;
  profile.avatarUrl = req.body.avatarUrl;

  await profile.save();
  res.json(profile);
});
