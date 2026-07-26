-- Sample data plus the least-privilege role the compose file connects as.
CREATE TABLE people (
    id      int PRIMARY KEY,
    name    text NOT NULL,
    ssn     text,
    country text
);
COMMENT ON TABLE people IS 'People, with one deliberately sensitive column';
COMMENT ON COLUMN people.country IS 'ISO 3166-1 alpha-2 country code';

CREATE TABLE orders (
    id        int PRIMARY KEY,
    person_id int REFERENCES people(id),
    total     numeric(12,2),
    placed_at timestamptz DEFAULT now()
);
COMMENT ON COLUMN orders.total IS 'Order total, gross, in EUR';

INSERT INTO people VALUES
    (1, 'Ada Lovelace', '123-45-6789', 'GB'),
    (2, 'Linus Torvalds', '987-65-4321', 'FI');
INSERT INTO orders (id, person_id, total) VALUES (1, 1, 99.90), (2, 2, 12.50), (3, 1, 250.00);

-- The role the MCP server uses: it may read, and nothing else.
CREATE ROLE reader LOGIN PASSWORD 'reader_pw';
GRANT CONNECT ON DATABASE postgres TO reader;
GRANT USAGE ON SCHEMA public TO reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO reader;
