
     ________                                   \\   ||   //
    /   __   \                                   \\  ||  //
   |   /  \   |    ______      _____     ______      __     _____
   |  |  _ |  |   |   _  \    /  _  \   |   _  \    |__|   /  _  \
   |  | / \|  |   |  |_)  )  |  / \  |  |  | \  \    __   |  / \  |
   |  | \  |  |   |      /   |  |_|  |  |  |  )  )  |  |  | (   ) |
   |   \_\    |   |  |\  \   |   _   |  |  |_/  /   |  |  |  \_/  |
    \_______  \   |__| \__\  |__| |__|  |______/    |__|   \_____/
            \__\
                                            ~ Tune In


QRadio - The Best Cyber Threat Intelligence Radio

QRadio is a tool/framework designed to consolidate cyber threats intelligence sources.
The goal of the project is to establish a robust modular framework for extraction of intelligence data from vetted sources.

It uses multiple threat intelligence sources for searching supplied data.

You can search the following data:
    - Domain
    - IPv4
    - Hash
    - Imphash
    - Mutex

Each station has different amount of input and output data (tunes):

# Output verbosity:
        -v,   --verbose             - Show verbose output
                                      Return CSV if not specified
# From Domain
    -   -100, --sonar_domain        - SONAR <domain> to IPv4, Hash, Score, URL, Blacklist
    -   -102, --domain_to_ipv4      - Resolve IPv4 to <domain>
    -   -103, --domain_to_hash      - Search Hash for <domain>
    -   -104, --domain_to_score     - Detection score for <domain>
    -   -105, --domain_to_url       - URL to analysis for <domain>
    -   -106, --domain_to_blacklist - Search <domain> in blacklists

# From IPv4
    -   -200, --sonar_ipv4          - SONAR <IPv4> to Domain, Hash, Score, Blacklist
    -   -201, --ipv4_to_domain      - Resolve Domain to <IPv4>
    -   -203, --ipv4_to_hash        - Search Hash for <IPv4>
    -   -204, --ipv4_to_score       - Detection score for <IPv4>
    -   -106, --ipv4_to_blacklist   - Search <IPv4> in blacklists

# From Hash
    -   -300, --sonar_hash          - SONAR <hash> to Domain, IPv4, Score, URL, Imphash
    -   -301, --hash_to_domain      - Search Domain for <hash>
    -   -302, --hash_to_ipv4        - Search IP for <hash>
    -   -304, --hash_to_score       - Detection score for <hash>
    -   -305, --hash_to_url         - URL to analysis for <hash>
    -   -307, --hash_to_imphash     - Search Imphash for <hash>

# Miscellaneous
    -   -401, --imphash_to_hash     - Search Hash with <imphash>
    -   -402, --mutex_to_hash       - Search Hash with <mutex>


## To change credentials for sources: /lib/config.py
Data Sources that already (+) integrated and pending to be integrated (-):

1) Threat Info database
    (+) threatcrowd.org
    (+) virustotal.com
    (+) cymon.io
    (+) IBM X-Force
    (+) metascan-online.com
    (+) totalhash.cymru.com

2) Sandboxes
    (+) malwr.com
    (-) hybrid-analysis.com
    (+) threatexpert.com

3) Blacklists
    (+) atrack.h3x.eu (Asprox)
    (+) feodotracker.abuse.ch
    (+) zeustracker.abuse.ch
    (+) malc0de.com
    (+) siteadvisor.com (McAfee)
    (-) palevotracker.abuse.ch
    (-) malwaredomainlist.com

4) Meta data Systems
    (-) shodan.io
    (-) censys.io
    (-) zoomeye.org

5) Other
    (+) foriguard.com (passive DNS)
    (+) hosts-file.net (score, passive DNS)