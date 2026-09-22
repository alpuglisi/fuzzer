// Manufactured, representative of the GraphQL-specific mass-assignment
// anti-pattern: an input typed as a generic JSON scalar instead of a
// schema-declared object type, defeating GraphQL's own type system as an
// allowlist.
const resolvers = {
  Mutation: {
    // input is declared in the schema as `JSONObject` (a generic scalar
    // some GraphQL servers ship for "flexibility") instead of a proper
    // `UpdateReviewInput` type -- the schema itself no longer constrains
    // which keys are legal.
    updateReview: async (_parent, { id, input }, ctx) => {
      const review = await ctx.db.Review.findByPk(id);
      Object.assign(review, input); // input is an arbitrary JSON object
      await review.save();
      return review;
    },
  },
};
