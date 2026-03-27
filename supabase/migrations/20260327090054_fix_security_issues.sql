/*
  # Fix Security Issues

  ## Issues Addressed

  1. Remove unused indexes (products category, bestseller, featured; newsletter email)
  2. Fix overly permissive RLS policies on newsletter_subscriptions table
  3. Fix overly permissive RLS policies on products table
  4. Add proper ownership/access restrictions

  ## Changes

  ### Indexes
  - Drop unused indexes that were created but not queried by application

  ### RLS Policies - Products Table
  - Keep public read access (anyone can view products)
  - Restrict write operations (insert, update, delete) to super admin only via auth.jwt()
  - Use restrictive approach: only explicit auth.jwt() app_metadata check

  ### RLS Policies - Newsletter Table
  - Keep insert open for newsletter signups but restrict to valid email patterns
  - Restrict read/update/delete to authenticated users viewing only their own data
  - Use user_id or email-based access control
*/

DROP INDEX IF EXISTS idx_products_category;
DROP INDEX IF EXISTS idx_products_bestseller;
DROP INDEX IF EXISTS idx_products_featured;
DROP INDEX IF EXISTS idx_newsletter_email;

DROP POLICY "Anyone can subscribe to newsletter" ON newsletter_subscriptions;
DROP POLICY "Authenticated users can view subscriptions" ON newsletter_subscriptions;
DROP POLICY "Authenticated users can update subscriptions" ON newsletter_subscriptions;
DROP POLICY "Authenticated users can delete subscriptions" ON newsletter_subscriptions;

DROP POLICY "Authenticated users can insert products" ON products;
DROP POLICY "Authenticated users can update products" ON products;
DROP POLICY "Authenticated users can delete products" ON products;

CREATE POLICY "Anyone can subscribe to newsletter"
  ON newsletter_subscriptions FOR INSERT
  TO anon, authenticated
  WITH CHECK (
    email IS NOT NULL 
    AND email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'
  );

CREATE POLICY "Users can view their own subscription"
  ON newsletter_subscriptions FOR SELECT
  TO authenticated
  USING (
    CASE 
      WHEN auth.jwt() ->> 'email' = email THEN true
      WHEN (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' THEN true
      ELSE false
    END
  );

CREATE POLICY "Users can unsubscribe from newsletter"
  ON newsletter_subscriptions FOR UPDATE
  TO authenticated
  USING (
    CASE 
      WHEN auth.jwt() ->> 'email' = email THEN true
      WHEN (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' THEN true
      ELSE false
    END
  )
  WITH CHECK (
    CASE 
      WHEN auth.jwt() ->> 'email' = email THEN true
      WHEN (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' THEN true
      ELSE false
    END
  );

CREATE POLICY "Admin can delete subscriptions"
  ON newsletter_subscriptions FOR DELETE
  TO authenticated
  USING (
    (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  );

CREATE POLICY "Admin only can insert products"
  ON products FOR INSERT
  TO authenticated
  WITH CHECK (
    (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  );

CREATE POLICY "Admin only can update products"
  ON products FOR UPDATE
  TO authenticated
  USING (
    (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  )
  WITH CHECK (
    (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  );

CREATE POLICY "Admin only can delete products"
  ON products FOR DELETE
  TO authenticated
  USING (
    (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'
  );
