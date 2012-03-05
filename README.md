# php-dmarc - A simple DMARC report parser for PHP

php-dmarc is a small PHP class I wrote to parse [DMARC](http://dmarc.org) aggregate reports and put the data in a MySQL database for easy analysis. The idea is that when recipients start supporting delivery of reports using HTTP, then this can form part of an endpoint that receives and automatically parses the reports.

Improvements/fixes welcome.

## Usage

- Set up your database. `tables.sql` contains the SQL needed to set up the tables.
- Use the `Dmarc_Aggregate_Parser` class to parse reports - you need to supply it with database credentials and a file to parse, and then run the `parse()` function with an array of files to parse. Something like this:

		$parser = new Dmarc_Aggregate_Parser( 'dbhost', 'dbuser', 'dbpass', 'dbname' );
		$parser->parse( array( 'report-file-1.xml', 'report-file-2.xml', 'report-file-3.xml' ) );

    The parser currently requires XML files (not the ZIP files), although I'm hoping to change that soon.

- Knock your self out analysing the data.

The `parse()` function returns `false` if it encounters any errors while parsing the data (`true` otherwise). To see what the errors were, use call `get_errors()` method, which will return an array of error messages.

## To do

Once recipients start supporting them:

- Failure report parser
- An endpoint for receiving reports using HTTP