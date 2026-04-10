-- Initial setup ----------------------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

create or replace function public.random_short_id(prefix text, len int default 12)
    returns text
    language plpgsql
    volatile
as $$
declare
    alphabet constant text := '23456789abcdefghjkmnpqrstvwxyz'; -- no 0/1/i/l/o
    out text := '';
    i int;
    idx int;
begin
    for i in 1..len loop
        idx := 1 + floor(random() * length(alphabet))::int;
        out := out || substr(alphabet, idx, 1);
    end loop;
    return prefix || out;
end;
$$;