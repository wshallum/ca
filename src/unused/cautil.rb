#!/usr/bin/ruby

# Used to create web database and sync ca database with web database.
#
# Web code not included, but you can probably guess what the website
# looks like from the tables.

require 'sqlite3'

def print_usage # usage {{{
  STDERR.puts <<EOF
usage: #{$0} command command-options

commands:
  newdb web-db-file
    creates a new website database in web-db-file
  sync web-db-file ca-db-file ca-name
    syncs web-db-file with ca-db-file
    The web-db-file's requests are entered into the ca-db-file
    and the ca-db-file's certificates are entered into the web-db-file
    The CA in the ca-db-file used is ca-name
EOF

  exit 1
end # }}}

if ARGV.length == 0 then
  print_usage
  # }}}
elsif ARGV[0] == "newdb" # newdb {{{
  dbname = ARGV[1]
  if dbname == nil then
    print_usage
  end
  
  db = SQLite3::Database.new(dbname, :driver => 'Native')
  db.execute_batch(<<EOS
    DROP TABLE IF EXISTS requests;
    DROP TABLE IF EXISTS certificates;
    CREATE TABLE certificates (
      id INTEGER PRIMARY KEY, 
      C VARCHAR(2), SP VARCHAR(64), L VARCHAR(64), 
      O VARCHAR(64), OU VARCHAR(64), CN VARCHAR(64), 
      validTo INTEGER NOT NULL, cert_data BLOB NOT NULL
    );
    CREATE TABLE requests (
      name VARCHAR(50) NOT NULL,
      email VARCHAR(50) NOT NULL,
      phone VARCHAR(50),
      notes VARCHAR(100),
      request_data BLOB NOT NULL,
      fingerprint BLOB NOT NULL
    );
EOS
)
  db.close
  # }}}
elsif ARGV[0] == "sync" # sync {{{
  if ARGV.length != 4 then
    print_usage
  end
  webdbname = ARGV[1]
  cadbname = ARGV[2]
  caname = ARGV[3]
  
  cadb = SQLite3::Database.new(cadbname, :driver => 'Native')
  cadb.busy_timeout(20 * 1000)
  cadb.execute("ATTACH DATABASE '#{webdbname}' AS webdb")
  cadb.transaction(:immediate) do
    # copy requests from webdb -> cadb
    insert_text =<<EOS
    INSERT INTO main.requests (recipient, received_on, request_type, request_data, fingerprint, notes, handled)
    SELECT ?, ?, 1, web.request_data, web.fingerprint, 
    'Name' || web.name || X'0A' ||
    'Email' || web.email || X'0A' ||
    COALESCE('Phone' || web.phone || X'0A', '') ||
    COALESCE(web.notes, ''),
    0
    FROM webdb.requests AS web
EOS
    cadb.execute(insert_text, caname, Time.now.to_i)
    cadb.execute('DELETE FROM webdb.requests')
    cadb.execute('DELETE FROM webdb.certificates')
    insert_text =<<EOS
    INSERT INTO webdb.certificates (id, C, SP, L, O, OU, CN, validTo, cert_data)
    SELECT cacerts.id, cacerts.C, cacerts.SP, cacerts.L, cacerts.O, 
    cacerts.OU, cacerts.CN, cacerts.validTo, cacerts.cert_data
    FROM main.certificates AS cacerts
    WHERE cacerts.issuer = ?
EOS

    cadb.execute(insert_text, caname)
  end
  cadb.close
  # }}}
else
  print_usage  
end

