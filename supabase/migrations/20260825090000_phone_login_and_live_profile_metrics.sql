-- Phone login key and live, role-aware profile metrics.
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS phone_login text;
UPDATE public.profiles SET phone_login = NULLIF(regexp_replace(COALESCE(phone, ''), '[^0-9]', '', 'g'), '') WHERE phone_login IS NULL;
CREATE INDEX IF NOT EXISTS profiles_phone_login_idx ON public.profiles(phone_login);

CREATE OR REPLACE FUNCTION public.normalize_profile_phone()
RETURNS trigger AS $$ BEGIN
  NEW.phone_login := NULLIF(regexp_replace(COALESCE(NEW.phone, ''), '[^0-9]', '', 'g'), '');
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS normalize_profile_phone_trigger ON public.profiles;
CREATE TRIGGER normalize_profile_phone_trigger BEFORE INSERT OR UPDATE OF phone ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.normalize_profile_phone();

-- Create the profile at the same time as the Auth account.  This is important
-- when Supabase email confirmation is enabled: signUp returns no browser
-- session until the verification link is opened, so a browser-side profile
-- insert would otherwise fail and leave a valid account unable to log in.
CREATE OR REPLACE FUNCTION public.create_profile_from_auth_data(p_user_id uuid, p_email text, p_metadata jsonb)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  metadata jsonb := COALESCE(p_metadata, '{}'::jsonb);
  requested_role text := COALESCE(NULLIF(COALESCE(p_metadata, '{}'::jsonb)->>'requested_role', ''), 'client');
  assigned_role text;
  full_name text;
BEGIN
  assigned_role := CASE WHEN requested_role IN ('client', 'freelancer', 'seller', 'worker') THEN requested_role ELSE 'client' END;
  IF EXISTS (SELECT 1 FROM public.admin_emails WHERE lower(email) = lower(COALESCE(p_email, ''))) THEN
    assigned_role := 'admin';
  END IF;
  full_name := trim(concat_ws(' ', metadata->>'first_name', metadata->>'last_name'));

  INSERT INTO public.profiles (
    user_id, role, first_name, middle_name, last_name, display_name, email,
    phone, country, state, city, address, bank_name, account_number,
    account_holder_name, kyc_level
  ) VALUES (
    p_user_id, assigned_role, metadata->>'first_name', metadata->>'middle_name',
    metadata->>'last_name', COALESCE(NULLIF(metadata->>'display_name', ''), NULLIF(full_name, ''), split_part(COALESCE(p_email, 'member'), '@', 1)),
    p_email, metadata->>'phone', COALESCE(NULLIF(metadata->>'country', ''), 'Nigeria'),
    metadata->>'state', metadata->>'city', metadata->>'address', metadata->>'bank_name',
    metadata->>'account_number', metadata->>'account_holder_name',
    CASE WHEN NULLIF(metadata->>'kyc_selfie', '') IS NULL THEN 0 ELSE 1 END
  ) ON CONFLICT (user_id) DO NOTHING;

  IF NULLIF(metadata->>'kyc_selfie', '') IS NOT NULL THEN
    INSERT INTO public.kyc_submissions (user_id, selfie_url, full_name)
    VALUES (p_user_id, metadata->>'kyc_selfie', NULLIF(full_name, ''));
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.create_profile_for_auth_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
  PERFORM public.create_profile_from_auth_data(NEW.id, NEW.email, NEW.raw_user_meta_data);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS create_profile_after_auth_signup ON auth.users;
CREATE TRIGGER create_profile_after_auth_signup
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.create_profile_for_auth_user();

-- Repairs older accounts that were created successfully but have no profile.
-- It uses the authenticated user's own Auth record and never accepts a user id
-- from the browser.
CREATE OR REPLACE FUNCTION public.ensure_own_profile()
RETURNS public.profiles
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  auth_user_row auth.users%ROWTYPE;
  result public.profiles%ROWTYPE;
BEGIN
  SELECT * INTO result FROM public.profiles WHERE user_id = auth.uid();
  IF FOUND THEN RETURN result; END IF;
  SELECT * INTO auth_user_row FROM auth.users WHERE id = auth.uid();
  IF NOT FOUND THEN RAISE EXCEPTION 'You must be signed in to create a profile.'; END IF;
  PERFORM public.create_profile_from_auth_data(auth_user_row.id, auth_user_row.email, auth_user_row.raw_user_meta_data);
  SELECT * INTO result FROM public.profiles WHERE user_id = auth.uid();
  RETURN result;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.ensure_own_profile() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.ensure_own_profile() TO authenticated;

CREATE OR REPLACE FUNCTION public.recalculate_profile_metrics(target_user uuid)
RETURNS void AS $$
DECLARE profile_role text; total_count integer := 0; success_count integer := 0; avg_rating numeric := 0; rating_count integer := 0;
BEGIN
  SELECT role INTO profile_role FROM public.profiles WHERE user_id = target_user;
  IF profile_role = 'client' THEN
    SELECT count(*), count(*) FILTER (WHERE status IN ('assigned','completed')) INTO total_count, success_count FROM public.jobs WHERE user_id = target_user;
  ELSE
    SELECT count(*), count(*) FILTER (WHERE status = 'completed') INTO total_count, success_count FROM public.jobs WHERE assigned_to = target_user;
  END IF;
  SELECT COALESCE(avg(stars),0), count(*) INTO avg_rating, rating_count FROM public.reviews WHERE reviewee_id = target_user;
  UPDATE public.profiles SET completion_rate = CASE WHEN total_count = 0 THEN 0 ELSE round((success_count::numeric / total_count::numeric) * 100, 2) END, rating = round(avg_rating, 2), review_count = rating_count WHERE user_id = target_user;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.refresh_metrics_from_job()
RETURNS trigger AS $$ BEGIN
  PERFORM public.recalculate_profile_metrics(COALESCE(NEW.user_id, OLD.user_id));
  IF COALESCE(NEW.assigned_to, OLD.assigned_to) IS NOT NULL THEN PERFORM public.recalculate_profile_metrics(COALESCE(NEW.assigned_to, OLD.assigned_to)); END IF;
  IF TG_OP = 'UPDATE' AND OLD.assigned_to IS DISTINCT FROM NEW.assigned_to AND OLD.assigned_to IS NOT NULL THEN PERFORM public.recalculate_profile_metrics(OLD.assigned_to); END IF;
  RETURN COALESCE(NEW, OLD);
END; $$ LANGUAGE plpgsql SECURITY DEFINER;
DROP TRIGGER IF EXISTS refresh_metrics_from_job_trigger ON public.jobs;
CREATE TRIGGER refresh_metrics_from_job_trigger AFTER INSERT OR UPDATE OR DELETE ON public.jobs FOR EACH ROW EXECUTE FUNCTION public.refresh_metrics_from_job();

CREATE OR REPLACE FUNCTION public.refresh_metrics_from_review()
RETURNS trigger AS $$ BEGIN PERFORM public.recalculate_profile_metrics(COALESCE(NEW.reviewee_id, OLD.reviewee_id)); RETURN COALESCE(NEW, OLD); END; $$ LANGUAGE plpgsql SECURITY DEFINER;
DROP TRIGGER IF EXISTS refresh_metrics_from_review_trigger ON public.reviews;
CREATE TRIGGER refresh_metrics_from_review_trigger AFTER INSERT OR UPDATE OR DELETE ON public.reviews FOR EACH ROW EXECUTE FUNCTION public.refresh_metrics_from_review();

DO $$ DECLARE p record; BEGIN FOR p IN SELECT user_id FROM public.profiles LOOP PERFORM public.recalculate_profile_metrics(p.user_id); END LOOP; END $$;
