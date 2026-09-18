-- Migration: add the blog `posts` table without touching existing data.
-- Use this on an already-populated database (so you keep your users/cart):
--   sudo mysql puppy_fort < sql/002_blog.sql
--
-- Fresh installs do not need this; sql/schema.sql already creates and seeds it.

USE puppy_fort;

CREATE TABLE IF NOT EXISTS posts (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  title        VARCHAR(160) NOT NULL,
  author       VARCHAR(80)  NOT NULL DEFAULT 'Ryder',
  body         TEXT,
  published_at DATE         NOT NULL
);

-- Seed only if the table is empty.
INSERT INTO posts (title, author, body, published_at)
SELECT * FROM (
  SELECT 'Five signs your puppy has outgrown their fort' AS title, 'Ryder' AS author,
         'When the drawbridge no longer intimidates the mailman, it may be time to upgrade. Here are five tell-tale signs, starting with the classic full-body flop over the ramparts.' AS body,
         DATE '2026-08-01' AS published_at
  UNION ALL SELECT 'The engineering behind chew-proof walls', 'Alice',
         'Our walls survive determined teething thanks to a three-layer laminate and a lot of testing by very motivated volunteers. We explain the science, and the snacks.', DATE '2026-08-14'
  UNION ALL SELECT 'A brief history of the squeaky drawbridge', 'Bob',
         'It began as a bug and became our most requested feature. This is the story of the squeak that launched a thousand zoomies.', DATE '2026-09-02'
  UNION ALL SELECT 'How to defend a fort against a determined cat', 'Ryder',
         'Cats respect no borders. We cover moat placement, watchtower staffing, and the strategic deployment of treats as a deterrent.', DATE '2026-09-15'
) seed
WHERE NOT EXISTS (SELECT 1 FROM posts);
