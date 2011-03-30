-- -----------------------------------------
-- upgrade path for Icinga IDOUtils 1.3.1
--
-- -----------------------------------------
-- Copyright (c) 2010-2011 Icinga Development Team (http://www.icinga.org)
--
-- Please check http://docs.icinga.org for upgrading information!
-- -----------------------------------------


-- -----------------------------------------
-- update dbversion
-- -----------------------------------------

MERGE INTO dbversion
USING DUAL ON (name='idoutils')
WHEN MATCHED THEN
UPDATE SET version='1.3.1'
WHEN NOT MATCHED THEN
INSERT (id, name, version) VALUES ('1', 'idoutils', '1.3.1');


