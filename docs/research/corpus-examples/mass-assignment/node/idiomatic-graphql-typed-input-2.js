// Manufactured, representative of a typed GraphQL input object in an
// Apollo Server / NestJS-style resolver (the same class of mitigation as
// Vendure's real UpdateProductInput, in a different, independently
// common GraphQL framework shape).
const resolvers = {
  Mutation: {
    // updateReviewInput is a typed GraphQL input type declared in the
    // schema as `{ rating: Int, comment: String }` -- only those two
    // fields can ever arrive here, whatever JSON the client sends.
    updateReview: async (_parent, { id, input: updateReviewInput }, ctx) => {
      const review = await ctx.db.Review.findByPk(id);
      review.rating = updateReviewInput.rating;
      review.comment = updateReviewInput.comment;
      await review.save();
      return review;
    },
  },
};
