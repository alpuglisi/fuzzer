# ForgeCart's merchant-admin surrounding pages (Phase C, see
# `storefront_controller.rb`'s own module docstring for the full rationale
# -- CC-LAB-0080/FR-LAB-84; the code elsewhere still cites MeadowMart's CC-LAB-0077/FR-LAB-81 -- flagged in CC-LAB-0245). None of these actions reads user-controlled
# input; the admin app's real vulnerability cells (customer mass-assignment
# update, product bulk-import deserialization) are `RailsEmitter`-rendered
# from the manifest, not defined here.
#
# CC-LAB-0245 (Browsable Labs Lane 5): HTML pages inside the shared layout,
# rendered by explicit template path (PA-0036). `customer_form` and
# `product_import_form` answer GET on the two POST pages' own URLs
# (`_REAL_PAGE_PROFILES`'s `get_page`): plain HTML forms whose action is the
# endpoint itself, never `form_with` (no per-request authenticity token --
# forgery protection is skipped globally and must not appear to be added,
# plan R3).
class AdminController < ApplicationController
  # The merchant-admin dashboard: links to every admin page.
  def dashboard
    render template: "admin/dashboard"
  end

  # An orders list -- real Shopify order management is a BPM-orchestrated
  # state machine this fixture does not model; an honest empty state.
  def orders
    render template: "admin/orders"
  end

  # GET /admin/customers/update -- the "edit customer" form. Exposes only
  # `user[bio]` (plan R4): a `user[username]` field would let one ordinary
  # submit rename the fixed `shopper1` record every later request looks up.
  def customer_form
    render template: "admin/customer_form"
  end

  # GET /admin/products/import -- the bulk product import form.
  def product_import_form
    render template: "admin/product_import_form"
  end
end
