<?php
class Dmarc_Aggregate_Parser {
	private $dbh;
	private $ready = false;
	private $errors = array();
	
	function __construct( $db_host, $db_user, $db_pass, $db_name ) {
		if( !$this->dbh = mysql_connect( $db_host, $db_user, $db_pass, true ) )
			return false;
		
		if( ! mysql_select_db( $db_name, $this->dbh ) )
			return false;

		$this->ready = true;
	}
	
	/**
	 * Parse a set of XML report files
	 *
	 * Supply an array of files to parse. Returns true on success or false if
	 * there were errors. To get a list of errors use the get_errors() method.
	**/
	function parse( $xmlfiles ) {
		if( !$this->ready ) {
			$this->errors[] = 'Failed to establish database connection.';
			return false;
		}

		if( !is_array( $xmlfiles ) )
			$xmlfiles = array( $xmlfiles );
		
		foreach( $xmlfiles as $xmlfile ) {
			$xml = new SimpleXMLElement( file_get_contents( $xmlfile ) );
			
			$date_begin = (int) $xml->report_metadata->date_range->begin;
			$date_end = (int) $xml->report_metadata->date_range->end;
			$org = $xml->report_metadata->org_name;
			$id = $xml->report_metadata->report_id;
			$domain = $xml->policy_published->domain;
			
			// no duplicates please
			$r = $this->query( $this->prepare( "SELECT org, report_id FROM report WHERE report_id = %s", $id ) );
		
			if( mysql_num_rows( $r ) ) {
				$this->errors[] =  "Stopped parsing report $id from $org: this report has already been parsed.";
				continue;
			}
			
			$result = $this->query( $this->prepare( "INSERT INTO report(date_begin, date_end, domain, org, report_id) VALUES (FROM_UNIXTIME(%s),FROM_UNIXTIME(%s), %s, %s, %s)", $date_begin, $date_end, $domain, $org, $id ) );
			
			if( false === $result ) {
				$this->errors[] = mysql_error( $this->dbh );
				continue;
			}
				
			$serial = mysql_insert_id( $this->dbh );
			
			// parse records
			foreach( $xml->record as $record ) {
				$row = $record->row;
				$results = $record->auth_results;
				
				$query = $this->prepare( "INSERT INTO rptrecord(serial,ip,count,disposition,reason,dkim_domain,dkim_result,spf_domain,spf_result) VALUES(%s, INET_ATON(%s), %s, %s, %s, %s, %s, %s, %s)", $serial, $row->source_ip, $row->count, $row->policy_evaluated->disposition, $row->policy_evaluated->reason->type, $results->dkim->domain, $results->dkim->result, $results->spf->domain, $results->spf->result ); 
				
				$result = $this->query( $query );

				if( false === $result )
					$this->errors[] = mysql_error( $this->dbh );
			}
		}

		return empty( $this->errors );
	}
	
	function get_errors() {
		return $this->errors;
	}
	
	private function query( $query ) {
		return mysql_query( $query, $this->dbh );
	}
	
	private function prepare( $query ) {
		$args = func_get_args();
		array_shift( $args );
		$query = preg_replace( '|(?<!%)%s|', "'%s'", $query ); // quote strings, avoiding escaped strings
		array_walk( $args, array( $this, 'esc' ) );
		return @vsprintf( $query, $args );
	}
	
	private function esc( $str ) {
		return mysql_real_escape_string( $str, $this->dbh );
	}
}