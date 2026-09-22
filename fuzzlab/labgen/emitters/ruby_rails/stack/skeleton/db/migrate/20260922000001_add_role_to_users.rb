# CC-LAB-0073 (Rails Phase B, CWE-915 mass assignment): adds the one
# privilege-relevant column the `permit_bang_unrestricted`/
# `strong_params_explicit_allowlist` pair needs to demonstrate mass
# assignment against a real column. Phase A's own migration
# (`20260101000000_create_users.rb`) deliberately carried no such column
# yet -- see that migration's own docstring.
#
# Also seeds the one real row both twins' controller looks up by username
# (`shopper1`) -- a real per-run SQLite database has no fixture-loading
# step of its own the way `php_laravel`'s `LiveBootHarness` seeds via raw
# SQL in `REAL_SCHEMA_SQL`; a migration's own `reversible`/`up` block plays
# that same real-seed-data role for this stack.
class AddRoleToUsers < ActiveRecord::Migration[8.1]
  def change
    add_column :users, :role, :string, null: false, default: "customer"
    reversible do |dir|
      dir.up do
        execute <<~SQL
          INSERT INTO users (username, email, bio, role, created_at, updated_at)
          VALUES ('shopper1', 'shopper1@example.com', '', 'customer', datetime('now'), datetime('now'))
        SQL
      end
    end
  end
end
