USE dmarc

CREATE TABLE report (
  serial int(10) unsigned NOT NULL AUTO_INCREMENT,
  date_begin timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  date_end timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  domain varchar(255) NOT NULL,
  org varchar(255) NOT NULL,
  report_id varchar(255) NOT NULL,
  PRIMARY KEY (serial),
  UNIQUE KEY domain (domain,report_id)
);

CREATE TABLE rptrecord (
  serial int(10) unsigned NOT NULL,
  ip varchar(39) NOT NULL,
  count int(10) unsigned NOT NULL,
  disposition enum('none','quarantine','reject'),
  reason varchar(255),
  dkim_domain varchar(255),
  dkim_result enum('none','pass','fail','neutral','policy','temperror','permerror'),
  spf_domain varchar(255),
  spf_result enum('none','neutral','pass','fail','softfail','temperror','permerror'),
  KEY serial (serial,ip)
);
