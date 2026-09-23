# ForgeCart's merchant-admin surrounding pages (Phase C, see
# `storefront_controller.rb`'s own module docstring for the full rationale
# -- CC-LAB-0077/FR-LAB-81). Both actions here are inert, read-only stubs
# with no user-controlled input; the admin app's real vulnerability cells
# (customer mass-assignment update, product bulk-import deserialization)
# are `RailsEmitter`-rendered from the manifest, not defined here.
class AdminController < ApplicationController
  # A static merchant-admin dashboard stub.
  def dashboard
    render plain: "ForgeCart admin -- merchant dashboard (lab fixture)."
  end

  # A static orders-list stub -- real Shopify order management is a
  # BPM-orchestrated state machine (payment auth -> inventory reservation
  # -> routing -> pick/pack -> ship, per the Walmart research this
  # category's sibling app cites); this fixture has no order-processing
  # pipeline to render from, so it stays an inert placeholder.
  def orders
    render json: { orders: [] }
  end
end
