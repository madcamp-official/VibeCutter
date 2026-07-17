CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS storage;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    CREATE ROLE authenticated NOLOGIN;
  END IF;
END $$;

CREATE OR REPLACE FUNCTION auth.uid()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$ SELECT NULL::uuid $$;

CREATE OR REPLACE FUNCTION storage.foldername(object_name text)
RETURNS text[]
LANGUAGE sql
IMMUTABLE
AS $$ SELECT string_to_array(object_name, '/') $$;

CREATE TABLE IF NOT EXISTS storage.buckets (
  id text PRIMARY KEY,
  name text NOT NULL UNIQUE,
  public boolean NOT NULL DEFAULT false,
  file_size_limit bigint,
  allowed_mime_types text[],
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS storage.objects (
  bucket_id text NOT NULL,
  name text NOT NULL,
  PRIMARY KEY (bucket_id, name)
);

ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
GRANT USAGE ON SCHEMA auth, storage TO authenticated;
