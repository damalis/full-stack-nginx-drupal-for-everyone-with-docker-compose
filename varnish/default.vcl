vcl 4.1;

import std;

backend default {
    .host = "webserver";
    .port = "90";
}

# Add hostnames, IP addresses and subnets that are allowed to purge content
acl purge {
    "webserver";
    "drupal";
    "localhost";
    "127.0.0.1";
    "::1";
}

sub vcl_recv {
    # Announce support for Edge Side Includes by setting the Surrogate-Capability header
    set req.http.Surrogate-Capability = "Varnish=ESI/1.0";
    
    # Remove empty query string parameters
    # e.g.: www.example.com/index.html?    
    if (req.url ~ "\?$") {
        set req.url = regsub(req.url, "\?$", "");
    }

    # Remove port number from host header
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
    
    # Sorts query string parameters alphabetically for cache normalization purposes.    
    set req.url = std.querysort(req.url);
    
    # Remove the proxy header to mitigate the httpoxy vulnerability
    # See https://httpoxy.org/    
    unset req.http.proxy;

    # Add X-Forwarded-Proto header when using https
    if (!req.http.X-Forwarded-Proto && (std.port(server.ip) == 443)) {
        set req.http.X-Forwarded-Proto = "https";
    }

    # Ban logic to remove multiple objects from the cache at once. Tailored to Drupal's cache invalidation mechanism
    if(req.method == "BAN") {
        if(!client.ip ~ purge) {
            return(synth(405, "BAN not allowed for this IP address"));
        }
        
        if (req.http.Purge-Cache-Tags) {
            ban("obj.http.Purge-Cache-Tags ~ " + req.http.Purge-Cache-Tags);
        }
        else {
            ban("obj.http.x-url ~ " + req.url + " && obj.http.x-host == " + req.http.host);
        }

        return (synth(200, "Ban added."));
    }

    # Purge logic to remove objects from the cache
    if(req.method == "PURGE") {
        if(!client.ip ~ purge) {
            return(synth(405,"PURGE not allowed for this IP address"));
        }
        return (purge);
    }
    
    # Only handle relevant HTTP request methods
    if (
        req.method != "GET" &&
        req.method != "HEAD" &&
        req.method != "PUT" &&
        req.method != "POST" &&
        req.method != "PATCH" &&
        req.method != "TRACE" &&
        req.method != "OPTIONS" &&
        req.method != "DELETE"
    ) {
        return (pipe);
    }

    # Remove tracking query string parameters used by analytics tools
    if (req.url ~ "(\?|&)(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=") {
        set req.url = regsuball(req.url, "&(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
        set req.url = regsuball(req.url, "\?(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "?");
        set req.url = regsub(req.url, "\?&", "?");
        set req.url = regsub(req.url, "\?$", "");
    }

    # Only cache GET and HEAD requests
    if ((req.method != "GET" && req.method != "HEAD") || req.http.Authorization) {
        return(pass);
    }

    # Mark static files with the X-Static-File header, and remove any cookies
    # X-Static-File is also used in vcl_backend_response to identify static files
    if (req.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|ogg|ogm|opus|otf|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
        set req.http.X-Static-File = "true";
        unset req.http.Cookie;
        return(hash);
    }

	# Don't cache the following pages
    if (req.url ~ "^/status.php$" ||
        req.url ~ "^/update.php$" ||
        req.url ~ "^/cron.php$" ||
        req.url ~ "^/admin$" ||
        req.url ~ "^/admin/.*$" ||
        req.url ~ "^/flag/.*$" ||
        req.url ~ "^.*/ajax/.*$" ||
        req.url ~ "^.*/ahah/.*$" ||
        req.url ~ "^/\.well-known/acme-challenge/") {
        return (pass);
    }

	# Remove all cookies except the session & NO_CACHE cookies
    if (req.http.Cookie) {
        set req.http.Cookie = ";" + req.http.Cookie;
        set req.http.Cookie = regsuball(req.http.Cookie, "; +", ";");
        set req.http.Cookie = regsuball(req.http.Cookie, ";(S?SESS[a-z0-9]+|NO_CACHE)=", "; \1=");
        set req.http.Cookie = regsuball(req.http.Cookie, ";[^ ][^;]*", "");
        set req.http.Cookie = regsuball(req.http.Cookie, "^[; ]+|[; ]+$", "");

        if (req.http.cookie ~ "^\s*$") {
            unset req.http.cookie;
        } else {
            return(pass);
        }
    }
    return(hash);
}

sub vcl_hash {
    # Create cache variations depending on the request protocol
    hash_data(req.http.X-Forwarded-Proto);
}

sub vcl_backend_response {
    # Inject URL & Host header into the object for asynchronous banning purposes
    set beresp.http.x-url = bereq.url;
    set beresp.http.x-host = bereq.http.host;

	# Serve stale content for 2 minutes after object expiration
	# Perform asynchronous revalidation while stale content is served
    set beresp.grace = 120s;

    # If the file is marked as static we cache it for 1 day
    if (bereq.http.X-Static-File == "true") {
        unset beresp.http.Set-Cookie;
        set beresp.ttl = 1d;
    }

    # If we dont get a Cache-Control header from the backend
    # we default to 1h cache for all objects
    if (!beresp.http.Cache-Control) {
        set beresp.ttl = 1h;
    }

    # Parse Edge Side Include tags when the Surrogate-Control header contains ESI/1.0
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi = true;
    }
}

sub vcl_deliver {
    # Cleanup of headers
    unset resp.http.x-url;
    unset resp.http.x-host;
    unset req.http.X-Static-File;
}
