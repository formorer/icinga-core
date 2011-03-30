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

INSERT INTO icinga_dbversion (name, version) VALUES ('idoutils', '1.3.1') ON DUPLICATE KEY UPDATE version='1.3.1';
