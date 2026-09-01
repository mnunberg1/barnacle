-- Demo dataset. Loaded automatically by the mysql container on first start.

-- The entrypoint creates MYSQL_USER with caching_sha2_password, whose handshake
-- would need TLS or an RSA key exchange. The tracer reads plaintext payloads,
-- so pin the demo user to the native handshake instead.
ALTER USER 'app'@'%' IDENTIFIED WITH mysql_native_password BY 'apppw';
FLUSH PRIVILEGES;

USE shop;

CREATE TABLE IF NOT EXISTS products (
  sku         VARCHAR(32) PRIMARY KEY,
  name        VARCHAR(128) NOT NULL,
  description TEXT,
  category    VARCHAR(64) NOT NULL,
  brand       VARCHAR(64) NOT NULL,
  price       DECIMAL(10,2) NOT NULL,
  stock       INT NOT NULL,
  rating      DECIMAL(3,2) NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
  id       VARCHAR(32) PRIMARY KEY,
  customer VARCHAR(64) NOT NULL,
  sku      VARCHAR(32) NOT NULL,
  status   VARCHAR(32) NOT NULL,
  qty      INT NOT NULL,
  total    DECIMAL(10,2) NOT NULL
);

INSERT INTO products VALUES
  ('SKU-001','Claw Hammer','Forged steel claw hammer with hickory handle','tools','acme',18.50,120,4.60),
  ('SKU-002','Ball Peen Hammer','Drop forged ball peen hammer, rust proof finish','tools','acme',22.00,45,4.20),
  ('SKU-003','Cordless Drill','18V brushless cordless drill with two batteries','tools','globex',129.99,17,4.80),
  ('SKU-004','Socket Set','40 piece metric socket set in a blow moulded case','tools','globex',64.25,0,4.10),
  ('SKU-005','Safety Goggles','Anti fog polycarbonate safety goggles','safety','initech',9.99,300,3.90),
  ('SKU-006','Work Gloves','Cut resistant nitrile coated work gloves','safety','initech',12.75,210,4.40),
  ('SKU-007','Tape Measure','8m rust proof tape measure with magnetic hook','tools','acme',11.00,88,4.70),
  ('SKU-008','Laser Level','Self levelling cross line laser level','tools','globex',89.00,6,4.90),
  ('SKU-009','Ear Defenders','Over ear hearing protection, 32dB SNR','safety','umbrella',24.50,64,4.30),
  ('SKU-010','Tool Bag','Heavy duty canvas tool bag with shoulder strap','storage','umbrella',34.95,52,4.00);

INSERT INTO orders VALUES
  ('ORD-1001','o''brien, inc.','SKU-003','shipped',2,259.98),
  ('ORD-1002','wayne industries','SKU-001','pending',10,185.00),
  ('ORD-1003','stark co','SKU-008','shipped',1,89.00),
  ('ORD-1004','o''brien, inc.','SKU-006','cancelled',5,63.75),
  ('ORD-1005','wayne industries','SKU-005','shipped',40,399.60),
  ('ORD-1006','tyrell corp','SKU-010','pending',3,104.85);

-- --- where the latency comes from ----------------------------------------
--
-- The demo needs some queries to be slow and the rest to be instant. That
-- rules out the obvious network-level trick: `tc qdisc ... netem delay` on
-- the server's interface adds the same delay to every packet, so it cannot
-- make five statements slow and fifteen fast. It is still worth having as a
-- baseline RTT -- see demo/netem.sh -- but it is not this.
--
-- So the latency lives in the SERVER, as a property of the objects being
-- queried rather than of the query text. Each of these views cross-joins a
-- one-row derived table containing a SLEEP. The derived table is materialised
-- exactly once per query, so the cost is paid once -- independent of how many
-- rows come back, which SLEEP() in a WHERE clause is not: there it runs per
-- row, and `... AND SLEEP(1.5) = 0` over three rows takes four and a half
-- seconds.
--
-- The delay is RANDOM, between 0.5 and 3 seconds, rather than a flat 1.5.
-- A fixed delay makes an unrealistically tidy picture: every slow query costs
-- exactly the same, so the latency histogram is a single spike and the average
-- never moves. Real slow queries scatter -- plan changes, buffer pool hits and
-- misses, lock waits, whatever else the server is doing -- and a cache has to
-- look good against a distribution, not against one number. RAND() is
-- re-evaluated per execution here, which is why this is in the derived table
-- and not folded into a constant.
--
-- Doing it here rather than in the application also keeps the client honest.
-- The statements it issues read like ordinary reporting queries, with nothing
-- in their text that says "this one is slow" -- which is what the queries a
-- real administrator would put in the cache list look like.

CREATE OR REPLACE VIEW inventory_report AS
  SELECT p.* FROM products p JOIN (SELECT SLEEP(0.5 + RAND() * 2.5) AS delay) d;

CREATE OR REPLACE VIEW order_history AS
  SELECT o.* FROM orders o JOIN (SELECT SLEEP(0.5 + RAND() * 2.5) AS delay) d;

CREATE OR REPLACE VIEW brand_rollup AS
  SELECT p.brand, COUNT(*) AS skus, SUM(p.stock) AS units,
         AVG(p.price) AS avg_price
  FROM products p JOIN (SELECT SLEEP(0.5 + RAND() * 2.5) AS delay) d
  GROUP BY p.brand;

CREATE OR REPLACE VIEW customer_spend AS
  SELECT o.customer, COUNT(*) AS orders_placed, SUM(o.total) AS spend
  FROM orders o JOIN (SELECT SLEEP(0.5 + RAND() * 2.5) AS delay) d
  GROUP BY o.customer;

CREATE OR REPLACE VIEW category_margin AS
  SELECT p.category, AVG(p.price) AS avg_price, AVG(p.rating) AS avg_rating,
         SUM(p.stock) AS units
  FROM products p JOIN (SELECT SLEEP(0.5 + RAND() * 2.5) AS delay) d
  GROUP BY p.category;
