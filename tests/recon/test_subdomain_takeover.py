from __future__ import annotations


class TestSubdomainTakeoverFingerprints:
    """The vendored fingerprint database itself — confirms the file loads
    and that the "only currently vulnerable" filter is doing real work,
    not just trusting it was implemented correctly."""

    def test_fingerprints_load_and_filter_to_vulnerable_only(self):
        from redteam_toolkit.recon.subdomain_takeover import _load_vulnerable_fingerprints
        entries = _load_vulnerable_fingerprints()
        assert len(entries) > 0
        assert all(e["vulnerable"] for e in entries)
        assert all(e["cname"] for e in entries)

    def test_aws_s3_is_present_and_vulnerable(self):
        """A real, currently-exploitable, very common one — confirms the
        filter isn't accidentally excluding everything real."""
        from redteam_toolkit.recon.subdomain_takeover import _load_vulnerable_fingerprints
        entries = _load_vulnerable_fingerprints()
        s3 = next(e for e in entries if e["service"] == "AWS/S3")
        assert "s3.amazonaws.com" in s3["cname"]

    def test_github_pages_excluded_as_no_longer_vulnerable(self):
        """GitHub Pages, Heroku, Netlify, and Shopify have all since added
        mandatory domain-verification, fixing the classic takeover vector
        — confirmed against the upstream project's CURRENT data before
        relying on it, not assumed from older security folklore. This is
        a regression test for that specific, easy-to-get-wrong nuance."""
        from redteam_toolkit.recon.subdomain_takeover import _load_vulnerable_fingerprints
        entries = _load_vulnerable_fingerprints()
        vulnerable_services = {e["service"] for e in entries}
        assert "Github" not in vulnerable_services
        assert "Heroku" not in vulnerable_services
        assert "Netlify" not in vulnerable_services
        assert "Shopify" not in vulnerable_services


class TestSubdomainTakeoverScan:
    def test_fingerprint_string_match_flags_finding(self, engagement_factory):
        from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule

        eng = engagement_factory()

        def fake_resolve(hostname):
            return ["mybucket.s3.amazonaws.com"] if hostname == "old.example.com" else None

        def fake_http(hostname):
            if hostname == "old.example.com":
                return "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>"
            return None

        m = SubdomainTakeoverModule(eng, resolve_cname_fn=fake_resolve, http_fetch_fn=fake_http)
        result = m.run("example.com", subdomains=["old.example.com", "safe.example.com"])

        assert result.error is None
        assert len(result.findings) == 1
        assert "old.example.com" in result.findings[0].title
        assert result.findings[0].extra["service"] == "AWS/S3"
        assert result.findings[0].severity.value == "HIGH"

    def test_nxdomain_fingerprint_flags_without_http_fetch(self, engagement_factory):
        """Elastic Beanstalk's fingerprint IS "the CNAME target doesn't
        resolve" — there's no page to fetch at all, so this must not
        depend on http_fetch_fn returning anything."""
        from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule

        eng = engagement_factory()
        http_called = {"count": 0}

        def fake_resolve(hostname):
            return ["myapp.elasticbeanstalk.com"] if hostname == "eb.example.com" else None

        def fake_http(hostname):
            http_called["count"] += 1
            return None

        m = SubdomainTakeoverModule(eng, resolve_cname_fn=fake_resolve, http_fetch_fn=fake_http)
        result = m.run("example.com", subdomains=["eb.example.com"])

        assert len(result.findings) == 1
        assert result.findings[0].extra["service"] == "AWS/Elastic Beanstalk"
        assert http_called["count"] == 0

    def test_cname_to_unrelated_host_is_not_flagged(self, engagement_factory):
        from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule

        eng = engagement_factory()
        m = SubdomainTakeoverModule(
            eng,
            resolve_cname_fn=lambda h: ["realserver.mycompany.com"],
            http_fetch_fn=lambda h: "Welcome to our actual website",
        )
        result = m.run("example.com", subdomains=["safe.example.com"])
        assert result.findings == []

    def test_vulnerable_cname_but_resource_still_claimed_is_not_flagged(self, engagement_factory):
        """CNAME pattern matches a known-vulnerable service, but the HTTP
        response doesn't match the unclaimed-resource fingerprint —
        meaning the bucket/app still exists and is in active use. Must
        not be flagged just because the CNAME pattern alone matched."""
        from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule

        eng = engagement_factory()
        m = SubdomainTakeoverModule(
            eng,
            resolve_cname_fn=lambda h: ["mybucket.s3.amazonaws.com"],
            http_fetch_fn=lambda h: "<html><body>My actual live website content</body></html>",
        )
        result = m.run("example.com", subdomains=["live.example.com"])
        assert result.findings == []

    def test_no_cname_at_all_is_skipped(self, engagement_factory):
        from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule

        eng = engagement_factory()
        m = SubdomainTakeoverModule(eng, resolve_cname_fn=lambda h: None, http_fetch_fn=lambda h: None)
        result = m.run("example.com", subdomains=["plain.example.com"])
        assert result.findings == []

    def test_explicit_subdomains_list_skips_self_discovery(self, engagement_factory):
        """Passing subdomains= directly must not trigger a passive_dns/
        crt.sh lookup at all."""
        from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule

        eng = engagement_factory()
        m = SubdomainTakeoverModule(
            eng,
            resolve_cname_fn=lambda h: None,
            http_fetch_fn=lambda h: None,
            ct_fetch_fn=lambda domain: (_ for _ in ()).throw(AssertionError("should not be called")),
        )
        result = m.run("example.com", subdomains=["a.example.com"])
        assert result.error is None

    def test_self_discovery_used_when_no_subdomains_given(self, engagement_factory):
        import json

        from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule

        eng = engagement_factory()
        canned_ct_response = json.dumps([{"name_value": "discovered.example.com"}])

        seen = []

        def fake_resolve(hostname):
            seen.append(hostname)
            return None

        m = SubdomainTakeoverModule(
            eng,
            resolve_cname_fn=fake_resolve,
            http_fetch_fn=lambda h: None,
            ct_fetch_fn=lambda domain: canned_ct_response,
        )
        m.run("example.com")  # no subdomains= passed
        assert "discovered.example.com" in seen

    def test_action_logged_as_recon_category(self, engagement_factory):
        from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule

        eng = engagement_factory()
        m = SubdomainTakeoverModule(eng, resolve_cname_fn=lambda h: None, http_fetch_fn=lambda h: None)
        m.run("example.com", subdomains=[])
        entries = eng.audit_log.read_all()
        assert entries[-1]["detail"]["category"] == "recon"
        assert entries[-1]["action"] == "subdomain_takeover_check"

    def test_out_of_scope_refused(self, engagement_factory):
        from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule

        eng = engagement_factory(targets=["*.example.com"])
        m = SubdomainTakeoverModule(eng, resolve_cname_fn=lambda h: None, http_fetch_fn=lambda h: None)
        result = m.run("evil.com", subdomains=[])
        assert result.error is not None

    def test_remediation_never_suggests_claiming_the_resource(self, engagement_factory):
        """Sanity check on the finding's own remediation text — this
        module detects, it must never imply the next step is to actually
        claim/register the dangling resource."""
        from redteam_toolkit.recon.subdomain_takeover import SubdomainTakeoverModule

        eng = engagement_factory()
        m = SubdomainTakeoverModule(
            eng,
            resolve_cname_fn=lambda h: ["mybucket.s3.amazonaws.com"],
            http_fetch_fn=lambda h: "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>",
        )
        result = m.run("example.com", subdomains=["old.example.com"])
        remediation = result.findings[0].remediation.lower()
        assert "without separate, explicit authorization" in remediation or "do not attempt" in remediation
