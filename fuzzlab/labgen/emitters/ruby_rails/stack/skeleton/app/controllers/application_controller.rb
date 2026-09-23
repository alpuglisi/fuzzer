# `ostruct` is a bundled-but-not-autoloaded default gem as of Ruby 3.3/
# Psych 4+ -- required here (CC-LAB-0074, insecure-deserialization) so a
# `YAML.unsafe_load`-rendered cell can actually instantiate a
# `!ruby/object:OpenStruct` tag from an adversarial YAML payload, which is
# exactly the observable divergence that cell's own live-boot test asserts
# against (`YAML.safe_load` raises `Psych::DisallowedClass` on the same
# input instead). Loaded globally, for both the vulnerable and secure
# twin, since requiring a stdlib class is not itself a vulnerability --
# only calling `unsafe_load` on tainted input is.
require "ostruct"

class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  # CC-LAB-0072/0073/0074 (Rails Phase B): every Phase B cell is a non-GET
  # write endpoint (PATCH/POST) a real HTTP client sends directly, with no
  # browser session/CSRF-token round trip of its own (RailsLiveBootHarness
  # sends form/raw-body requests, never renders a form page first) --
  # CSRF is an orthogonal concern from every vulnerability class this lane
  # builds, so it is disabled here rather than forcing every live-boot test
  # to first mint a real authenticity token for a page that does not exist.
  skip_forgery_protection
end
