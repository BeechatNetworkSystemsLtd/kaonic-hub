DELETE FROM audit
WHERE id <= (SELECT MAX(id) FROM audit) - ?1;
