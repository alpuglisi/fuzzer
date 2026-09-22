# Minimal, real Rails migration (Phase A) -- the "users-equivalent table"
# a live-boot harness's real per-run SQLite database needs at minimum, per
# docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md's Phase A task instructions.
#
# Not used by this dispatch's own illustrative cell (a pure reflected
# request-param -> response-body echo touches no table at all) -- checked
# in now so RailsLiveBootHarness's real `bin/rails db:prepare` step has a
# real schema to migrate, and so Phase B's later, separate lane (the actual
# CWE-915 mass-assignment / stored-XSS modules Shopify's own research
# shortlisted) has a real users table already wired into the harness rather
# than needing to invent the first one. Kept deliberately minimal: no
# password/session columns yet, since no Phase A cell reads or writes them.
class CreateUsers < ActiveRecord::Migration[8.1]
  def change
    create_table :users do |t|
      t.string :username, null: false
      t.string :email, null: false
      t.string :bio

      t.timestamps
    end
    add_index :users, :username, unique: true
  end
end
