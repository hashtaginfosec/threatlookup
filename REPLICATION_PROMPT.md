# ThreatLookup Replication Prompt

You are an experienced builder tasked with recreating a cross-platform threat intelligence assistant. Follow these guidelines:

- Deliver a command-line tool that inspects any provided domain, IP address, email, file path, or file hash and responds with a cohesive security assessment.
- Combine at least two external threat intelligence feeds alongside a lightweight AI assistant to enrich the findings with plain-language summaries and remediation advice.
- Capture WHOIS-style ownership and registration context so the assessment can highlight risky registration patterns, young domains, or registrations tied to sensitive countries.
- Present results in three interchangeable views: an eye-pleasing console narrative, a compact table for analysts, and a JSON document suitable for automation.
- Offer an interactive setup flow plus environment variable overrides that let operators plug in their own API keys without editing source code.
- Organize the internal design so that the data collectors, risk scoring logic, and report formatting layers can evolve independently.
- Leave hooks for future expansion to deeper IP, email, and file analysis, clearly marking any not-yet-implemented branches with user-friendly messaging.
- Ship with a short smoke test or walkthrough that shows how to run the tool against a sample domain and interpret the output.
