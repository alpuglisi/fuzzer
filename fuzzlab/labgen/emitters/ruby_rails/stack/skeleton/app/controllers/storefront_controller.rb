# ForgeCart's storefront-facing surrounding pages (Phase C page/route
# identity, `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4/§9.5 --
# CC-LAB-0080/FR-LAB-84; the code elsewhere still cites MeadowMart's CC-LAB-0077/FR-LAB-81 -- flagged in CC-LAB-0245). Checked into the skeleton itself, not emitted by
# any `Cell`/manifest: these actions carry no vulnerability and read no
# user-controlled input at all, so there is no minimal-pair module to author
# for them -- they exist only to make the app's real vulnerability cells
# ("search" -> reflected XSS, the two "webhooks" endpoints, the admin
# customer/product endpoints) read as pages inside one coherent Shopify-style
# merchant storefront.
#
# CC-LAB-0245 (Browsable Labs Lane 5): every action renders a real HTML page
# inside the shared ForgeCart layout (it used to return plain text or JSON),
# always by explicit template path (PA-0036 -- never through the inflector).
#
# `/search` (the one storefront route with real user input) is NOT here --
# it is `RailsEmitter`-rendered from the existing ("xss", "html_body")
# shape, at whichever cell the app's manifest assigns to
# `LABGEN-RR-RP-0001` (see `lab/manifests/shopify_forgecart_real_pages.yaml`).
class StorefrontController < ApplicationController
  # The storefront homepage: brand, description, links to every page.
  def home
    render template: "storefront/home"
  end

  # A product-catalog page -- real Shopify product/collection pages are
  # server-rendered via Liquid over real product data
  # (docs/research/site-architecture-survey-functionality-shopify.md §1);
  # this fixture has no product database to render from, so it shows an
  # honest empty state rather than fabricating one.
  def products
    render template: "storefront/products"
  end

  # A cart page -- real Shopify hands off to a separate, PCI-scoped checkout
  # subsystem this lab does not model; an empty cart.
  def cart
    render template: "storefront/cart"
  end

  # CC-LAB-0245: the catalog of illustrative `/cell/*` routes (design-contract
  # point 5), read at request time from Rails' own route table -- the served
  # routes are the list by construction (PA-0003/PA-0021: no second,
  # independently maintained copy). GET routes are linked; the rest are
  # listed with their verb (plan R8).
  def catalog
    @cell_routes = Rails.application.routes.routes.filter_map do |route|
      path = route.path.spec.to_s.delete_suffix("(.:format)")
      next unless path.start_with?("/cell/")

      [path, route.verb]
    end.uniq.sort
    render template: "storefront/catalog"
  end
end
