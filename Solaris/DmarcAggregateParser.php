<?php
/**
 * A simple DMARC report parser for PHP
 * Samir Shah (http://rayofsolaris.net)
 * License: MIT
 **/
namespace Solaris;

class DmarcAggregateParser {
	private $dbh;
	private $ready = false;
	private $errors = array();

	function __construct( $db_host, $db_user, $db_pass, $db_name ) {
		try {
			$this->dbh = new \PDO( "mysql:host=$db_host;dbname=$db_name", $db_user, $db_pass );
		}
		catch( PDOException $e ) {
			$this->errors[] = 'Failed to establish database connection.';
			$this->errors[] = $e->getMessage();
			return false;
		}

		$this->dbh->setAttribute( \PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION );
		$this->ready = true;
	}

	/**
	 * Parse a set of XML report files
	 *
	 * Supply an array of files to parse. Returns true on success or false if
	 * there were errors. To get a list of errors use the get_errors() method.
	 * You can supply either ZIP files or XML files.
	**/
	function parse( $files ) {
		if( !$this->ready )
			return false;

		if( !is_array( $files ) )
			$files = array( $files );

		foreach( $files as $file ) {
			if( strtolower( substr( $file, -4 ) ) == '.zip' ) {
				$data = $this->unzip( $file );
				if( !$data ) {
					$this->errors[] = "Failed to open zip file: $zipfile";
					return false;
				}
			}
			else {
				$data = file_get_contents( $file );
			}

			$xml = new \SimpleXMLElement( $data );

			$date_begin = (int) $xml->report_metadata->date_range->begin;
			$date_end = (int) $xml->report_metadata->date_range->end;
			$org = $xml->report_metadata->org_name;
			$id = $xml->report_metadata->report_id;
			$domain = $xml->policy_published->domain;

			// no duplicates please
			$sth = $this->dbh->prepare( "SELECT org, report_id FROM report WHERE report_id = :report_id" );
			$sth->execute( array( 'report_id' => $id ) );
			if( $sth->rowCount() ) {
				$this->errors[] =  "Stopped parsing report $id from $org: this report has already been parsed.";
				continue;
			}

			try {
				$sth = $this->dbh->prepare( "INSERT INTO report(date_begin, date_end, domain, org, report_id) VALUES (FROM_UNIXTIME(:date_begin),FROM_UNIXTIME(:date_end), :domain, :org, :id)" );
				$sth->execute( array( 'date_begin' => $date_begin, 'date_end' => $date_end, 'domain' => $domain, 'org' => $org, 'id' => $id ) );
			}
			catch( PDOException $e ) {
				$this->errors[] = $e->getMessage();
				continue;
			}

			$serial = $this->dbh->lastInsertId();

			// parse records
			foreach( $xml->record as $record ) {
				$row = $record->row;
				$results = $record->auth_results;

				// Google incorrectly uses "hardfail" in SPF results
				if( $results->spf->result == 'hardfail' )
					$results->spf->result = 'fail';

				try {
					$sth = $this->dbh->prepare( "INSERT INTO rptrecord(serial,ip,count,disposition,reason,dkim_domain,dkim_result,spf_domain,spf_result) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)" );
					$sth->execute( array( $serial, $row->source_ip, $row->count, $row->policy_evaluated->disposition, $row->policy_evaluated->reason->type, $results->dkim->domain, $results->dkim->result, $results->spf->domain, $results->spf->result ) );
				}
				catch( PDOException $e ) {
					$this->errors[] = $e->getMessage();
				}
			}
		}

		return empty( $this->errors );
	}

	function get_errors() {
		return $this->errors;
	}

	/*
	 * Unzip a zipped DMARC report and return the contents.
	 * Assumes (for now) that there is only one file to extract
	 */
	private function unzip( $zipfile ) {
		$zip = zip_open( $zipfile );
		if( !is_resource( $zip ) )
			return false;

		$data = false;
		$zip_entry = zip_read( $zip );

		if( zip_entry_open( $zip, $zip_entry, 'r' ) ) {
			$data = zip_entry_read( $zip_entry, zip_entry_filesize( $zip_entry ) );
			zip_entry_close( $zip_entry );
		}
		zip_close( $zip );
		return $data;
	}
}
