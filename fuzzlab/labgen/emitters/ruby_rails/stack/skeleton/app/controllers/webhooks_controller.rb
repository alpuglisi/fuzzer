# ForgeCart's webhook delivery console (CC-LAB-0245, Browsable Labs Lane 5).
# The two webhook receivers (`/webhooks/orders/create`,
# `/webhooks/customers/update`) are genuine machine-to-machine `api`
# endpoints: Shopify POSTs a raw JSON body signed in an
# `X-Shopify-Hmac-SHA256` header, which no HTML form can set. They keep their
# JSON wire contract; this action answers GET on each receiver URL with one
# shared `fetch()` client page (the way a merchant would replay a delivery),
# so the endpoint is reachable by clicking through the site.
#
# The page reads no request data and never embeds or computes the webhook
# secret (plan R6: that would make the *secure* twin forgeable too, changing
# the modelled weakness, a timing side channel). Both topics therefore serve a
# byte-identical page; its script posts to `window.location.pathname`.
class WebhooksController < ApplicationController
  def console
    render template: "webhooks/console"
  end
end
