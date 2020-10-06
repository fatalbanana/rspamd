%%{

  machine smtp_date_parser;
  include smtp_base "smtp_base.rl";
  include smtp_date "smtp_date.rl";

  main := date_time;
}%%

#include "smtp_parsers.h"
#include "util.h"

%% write data;

guint64
rspamd_parse_smtp_date (const char *data, size_t len, GError **err)
{
  const gchar *p = data, *pe = data + len, *eof = data + len, *tmp = data;
  struct tm tm;
  glong tz = 0;
  gint cs = 0;

  memset (&tm, 0, sizeof (tm));

  %% write init;
  %% write exec;

  if ( cs < %%{ write first_final; }%% ) {
    g_set_error (err, g_quark_from_static_string ("smtp_date"), cs, "invalid date at offset %d (%c), state %d",
        p - data, *p, cs);
    return (guint64)(-1);
  }

  return rspamd_tm_to_time (&tm, tz);
}