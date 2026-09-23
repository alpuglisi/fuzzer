# ForgeCart's storefront-facing surrounding pages (Phase C page/route
# identity, `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4/§9.5 --
# CC-LAB-0077/FR-LAB-81). Checked into the skeleton itself, not emitted by
# any `Cell`/manifest: these three actions carry no vulnerability and no
# user-controlled input at all, so there is no minimal-pair module to
# author for them -- they exist only to make the app's real vulnerability
# cells ("search" -> reflected XSS, the two "webhooks" endpoints, the
# admin customer/product endpoints) read as pages inside one coherent
# Shopify-style merchant storefront, per this dispatch's own instructions
# ("surrounding pages can be simple/inert").
#
# `/search` (the one storefront route with real user input) is NOT here --
# it is `RailsEmitter`-rendered from the existing ("xss", "html_body")
# shape, at whichever cell the app's manifest assigns to
# `LABGEN-RR-RP-0001` (see `lab/manifests/shopify_forgecart_real_pages.yaml`).
class StorefrontController < ApplicationController
  # A static storefront landing page.
  def home
    render plain: "ForgeCart -- a Shopify-style merchant storefront (lab fixture)."
  end

  # A static product-catalog stub -- real Shopify product/collection pages
  # are server-rendered via Liquid over real product data
  # (docs/research/site-architecture-survey-functionality-shopify.md §1);
  # this fixture has no product database to render from, so it stays an
  # inert placeholder rather than fabricating one.
  def products
    render json: { products: [] }
  end

  # A static cart stub -- real Shopify hands off to a separate, PCI-scoped
  # checkout subsystem this lab does not model (out of scope per this
  # dispatch's own instructions).
  def cart
    render json: { items: [] }
  end
end
