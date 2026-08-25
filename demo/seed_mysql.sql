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
