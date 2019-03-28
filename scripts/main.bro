##! Add an excerpt of HTTP POST bodies into the HTTP log.

@load base/protocols/http

module Corelight;

export {
	## The length of POST bodies to extract.
	const http_post_body_length = 200 &redef;
	## Terget list (table [HTTP_HOST] of set [HTTP URIs])
	## Example:
	##     redef target_list += { ["example.com"] = set("/api", "/submit") };
	const target_list: table[string] of set[string] &redef;
}

redef record HTTP::Info += {
	post_body: string &log &optional;
};

event log_post_bodies(f: fa_file, data: string)
	{
	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];
		if ( ! c$http?$post_body )
			c$http$post_body = "";
		# If we are already above the captured size here, just return.
		if ( |c$http$post_body| > http_post_body_length )
			return;

		c$http$post_body = c$http$post_body + data;
		if ( |c$http$post_body| > http_post_body_length )
			{
			c$http$post_body = c$http$post_body[0:http_post_body_length] + "...";
			}
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( is_orig && c?$http && c$http?$method && c$http?$host && c$http?$uri 
		 && c$http$method == "POST" && c$http$host in target_list )
		{
		for ( u in target_list[c$http$host] )
			{
			if (u in c$http$uri)
				Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=log_post_bodies]);
				return;
			}
		}
	}
