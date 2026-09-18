-- Ryder's Puppy Fort Factory - database schema and seed data.
-- Import with:  mysql -u root -p < sql/schema.sql
--
-- NOTE: passwords are stored as unsalted MD5. That is itself a weakness, kept
-- deliberately so the classic SQL-injection login works. It is documented in
-- VULNERABILITIES.md and is separate from the SQLi/XSS focus of this lab.

CREATE DATABASE IF NOT EXISTS puppy_fort CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE puppy_fort;

DROP TABLE IF EXISTS cart_items;
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  username   VARCHAR(50)  NOT NULL UNIQUE,
  email      VARCHAR(120) NOT NULL,
  password   VARCHAR(64)  NOT NULL,          -- unsalted MD5 (intentional)
  full_name  VARCHAR(120) NOT NULL DEFAULT '',
  bio        TEXT,
  address    VARCHAR(255) NOT NULL DEFAULT '',
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(120)   NOT NULL,
  description TEXT,
  price       DECIMAL(10,2)  NOT NULL DEFAULT 0,
  category    VARCHAR(60)    NOT NULL DEFAULT 'general',
  stock       INT            NOT NULL DEFAULT 0
);

CREATE TABLE cart_items (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  user_id    INT NOT NULL,
  product_id INT NOT NULL,
  quantity   INT NOT NULL DEFAULT 1,
  added_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_product (user_id, product_id)
);

CREATE TABLE posts (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  title        VARCHAR(160) NOT NULL,
  author       VARCHAR(80)  NOT NULL DEFAULT 'Ryder',
  body         TEXT,
  published_at DATE         NOT NULL
);

-- Seed users (password shown in the comment).
INSERT INTO users (username, email, password, full_name, bio, address) VALUES
('admin', 'admin@puppyfort.test', MD5('admin123'),  'Ryder Ryderson', 'Chief Fort Architect and head of biscuit security.', '1 Kennel Lane'),
('alice', 'alice@puppyfort.test', MD5('password1'), 'Alice Waggins',  'Proud parent of three golden retrievers.',           '22 Fetch Street'),
('bob',   'bob@puppyfort.test',   MD5('letmein'),   'Bob Barker',     'Here for the squeaky drawbridges.',                  '8 Bark Avenue');

-- Seed products.
INSERT INTO products (name, description, price, category, stock) VALUES
('Puppy Fort Deluxe',        'Our flagship four-tower fort with a plush moat and treat drawbridge.', 149.99, 'forts',       12),
('Chew-Proof Fort Walls',    'Reinforced modular walls that survive the most determined teether.',    59.99,  'forts',       40),
('Squeaky Drawbridge',       'A drawbridge that squeaks with every triumphant crossing.',            24.99,  'accessories', 75),
('Plush Watchtower',         'A cozy lookout tower for the vigilant guard pup.',                      39.99,  'accessories', 30),
('Treat-Dispensing Moat',    'Fill the moat with kibble; lower the bridge to release the feast.',     34.99,  'accessories', 25),
('Puppy Fort Starter Kit',   'Everything a first-time fort builder needs, in one box.',               89.99,  'forts',       18),
('Camo Fort Cover',          'For stealthy pups who prefer a low profile.',                           19.99,  'accessories', 60),
('Peanut Butter Fort Bricks','Edible bricks. Structural for about four minutes.',                     14.99,  'treats',      100),
('Bacon Battlements',        'Crunchy bacon-flavoured battlements for the fort skyline.',             12.99,  'treats',      100),
('Glow-in-the-Dark Flags',   'Light up the ramparts for night patrol.',                              9.99,   'accessories', 80);

-- Seed blog posts (used by blog.php and blog_post.php).
INSERT INTO posts (title, author, body, published_at) VALUES
('Five signs your puppy has outgrown their fort', 'Ryder', 'When the drawbridge no longer intimidates the mailman, it may be time to upgrade. Here are five tell-tale signs, starting with the classic full-body flop over the ramparts.', '2026-08-01'),
('The engineering behind chew-proof walls',       'Alice', 'Our walls survive determined teething thanks to a three-layer laminate and a lot of testing by very motivated volunteers. We explain the science, and the snacks.', '2026-08-14'),
('A brief history of the squeaky drawbridge',     'Bob',   'It began as a bug and became our most requested feature. This is the story of the squeak that launched a thousand zoomies.', '2026-09-02'),
('How to defend a fort against a determined cat', 'Ryder', 'Cats respect no borders. We cover moat placement, watchtower staffing, and the strategic deployment of treats as a deterrent.', '2026-09-15');
