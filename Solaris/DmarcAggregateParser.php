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
			switch (true) {
				case strtolower( substr( $file, -4 ) ) === '.zip':
					$data = $this->unzip( $file );
					if( !$data ) {
						$this->errors[] = "Failed to open zip file: $file";
						return false;
					}
					break;
				case strtolower( substr( $file, -3 ) ) === '.gz':
					$data = $this->gunzip( $file );
					if( !$data ) {
						$this->errors[] = "Failed to open gzip file: $file";
						return false;
					}
					break;
				default:
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
		if (!$zip_entry) {
			return false;
		}

		if( zip_entry_open( $zip, $zip_entry, 'r' ) ) {
			$data = zip_entry_read( $zip_entry, zip_entry_filesize( $zip_entry ) );
			zip_entry_close( $zip_entry );
		}
		zip_close( $zip );
		return $data;
	}

	/*
	 * Unzip a gzipped DMARC report and return the contents.
	 */
	private function gunzip( $zipfile ) {
		$gzdata = file_get_contents($zipfile);
		if (!$gzdata) {
			return false;
		}

		if (function_exists('gzdecode')) {
			$data = gzdecode($gzdata);
		} else {
			$data = $this->gzdecode($gzdata);
		}
		if (!$data) {
			return false;
		}

		return $data;
	}

	/*
	 * http://php.net/gzdecode#82930
	 */

	private function gzdecode($data, &$filename='', &$error='', $maxlength=null) {
	    $len = strlen($data);
	    if ($len < 18 || strcmp(substr($data,0,2),"\x1f\x8b")) {
	        $error = "Not in GZIP format.";
	        return null;  // Not GZIP format (See RFC 1952)
	    }
	    $method = ord(substr($data,2,1));  // Compression method
	    $flags  = ord(substr($data,3,1));  // Flags
	    if ($flags & 31 != $flags) {
	        $error = "Reserved bits not allowed.";
	        return null;
	    }
	    // NOTE: $mtime may be negative (PHP integer limitations)
	    $mtime = unpack("V", substr($data,4,4));
	    $mtime = $mtime[1];
	    $xfl   = substr($data,8,1);
	    $os    = substr($data,8,1);
	    $headerlen = 10;
	    $extralen  = 0;
	    $extra     = "";
	    if ($flags & 4) {
	        // 2-byte length prefixed EXTRA data in header
	        if ($len - $headerlen - 2 < 8) {
	            return false;  // invalid
	        }
	        $extralen = unpack("v",substr($data,8,2));
	        $extralen = $extralen[1];
	        if ($len - $headerlen - 2 - $extralen < 8) {
	            return false;  // invalid
	        }
	        $extra = substr($data,10,$extralen);
	        $headerlen += 2 + $extralen;
	    }
	    $filenamelen = 0;
	    $filename = "";
	    if ($flags & 8) {
	        // C-style string
	        if ($len - $headerlen - 1 < 8) {
	            return false; // invalid
	        }
	        $filenamelen = strpos(substr($data,$headerlen),chr(0));
	        if ($filenamelen === false || $len - $headerlen - $filenamelen - 1 < 8) {
	            return false; // invalid
	        }
	        $filename = substr($data,$headerlen,$filenamelen);
	        $headerlen += $filenamelen + 1;
	    }
	    $commentlen = 0;
	    $comment = "";
	    if ($flags & 16) {
	        // C-style string COMMENT data in header
	        if ($len - $headerlen - 1 < 8) {
	            return false;    // invalid
	        }
	        $commentlen = strpos(substr($data,$headerlen),chr(0));
	        if ($commentlen === false || $len - $headerlen - $commentlen - 1 < 8) {
	            return false;    // Invalid header format
	        }
	        $comment = substr($data,$headerlen,$commentlen);
	        $headerlen += $commentlen + 1;
	    }
	    $headercrc = "";
	    if ($flags & 2) {
	        // 2-bytes (lowest order) of CRC32 on header present
	        if ($len - $headerlen - 2 < 8) {
	            return false;    // invalid
	        }
	        $calccrc = crc32(substr($data,0,$headerlen)) & 0xffff;
	        $headercrc = unpack("v", substr($data,$headerlen,2));
	        $headercrc = $headercrc[1];
	        if ($headercrc != $calccrc) {
	            $error = "Header checksum failed.";
	            return false;    // Bad header CRC
	        }
	        $headerlen += 2;
	    }
	    // GZIP FOOTER
	    $datacrc = unpack("V",substr($data,-8,4));
	    $datacrc = sprintf('%u',$datacrc[1] & 0xFFFFFFFF);
	    $isize = unpack("V",substr($data,-4));
	    $isize = $isize[1];
	    // decompression:
	    $bodylen = $len-$headerlen-8;
	    if ($bodylen < 1) {
	        // IMPLEMENTATION BUG!
	        return null;
	    }
	    $body = substr($data,$headerlen,$bodylen);
	    $data = "";
	    if ($bodylen > 0) {
	        switch ($method) {
	        case 8:
	            // Currently the only supported compression method:
	            $data = gzinflate($body,$maxlength);
	            break;
	        default:
	            $error = "Unknown compression method.";
	            return false;
	        }
	    }  // zero-byte body content is allowed
	    // Verifiy CRC32
	    $crc   = sprintf("%u",crc32($data));
	    $crcOK = $crc == $datacrc;
	    $lenOK = $isize == strlen($data);
	    if (!$lenOK || !$crcOK) {
	        $error = ( $lenOK ? '' : 'Length check FAILED. ') . ( $crcOK ? '' : 'Checksum FAILED.');
	        return false;
	    }
	    return $data;
	}
}
