// Excerpt of Vendure, packages/core/src/service/services/product.service.ts
// (GPL-3.0 Community Edition). Source: repo vendure-ecommerce/vendure,
// commit cccf0a72ec1b88a4e00ea3cffad4d30b35aaf7e7.
// License note: GPL-3.0 (copyleft) -- kept to the single method signature,
// per this corpus's copyleft-handling rule.

async update(ctx: RequestContext, input: UpdateProductInput): Promise<Translated<Product>> {
    const product = await this.connection.getEntityOrThrow(ctx, Product, input.id, {
        channelId: ctx.channelId,
        relations: ['facetValues', 'facetValues.channels'],
    });
    await this.slugValidator.validateSlugs(ctx, input, ProductTranslation);
    const updatedProduct = await this.translatableSaver.update({
        ctx,
        input,
        entityType: Product,
        translationType: ProductTranslation,
    });
    return assertFound(this.findOne(ctx, updatedProduct.id));
}
