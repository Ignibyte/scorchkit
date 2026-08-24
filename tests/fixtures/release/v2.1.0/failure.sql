-- The first statement commits under psql's ordinary autocommit mode. The second fails, leaving a
-- deliberately damaged rehearsal database whose recovery must come from the verified snapshot.
CREATE TABLE release_failure_marker (id INTEGER PRIMARY KEY);
SELECT 1 / 0;

